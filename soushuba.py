# -*- coding: utf-8 -*-
"""
搜书吧自动签到和发布动态脚本
增强版 - 解决404错误问题
"""
import os
import re
import sys
import time
import random
import logging
from copy import deepcopy
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup

# 配置日志
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

ch = logging.StreamHandler(stream=sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)

# 通用配置
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Connection": "keep-alive"
}

def random_delay(min_sec=1, max_sec=3):
    """随机延迟"""
    time.sleep(random.uniform(min_sec, max_sec))

def get_final_url(url: str, max_redirects=5):
    """获取最终重定向URL"""
    try:
        session = requests.Session()
        session.max_redirects = max_redirects
        response = session.head(url, headers=DEFAULT_HEADERS, allow_redirects=True, timeout=15, verify=False)
        return response.url
    except Exception as e:
        logger.warning(f"获取最终URL失败: {e}")
        return url

def find_soushu_link(html_content):
    """从HTML内容中查找搜书吧链接"""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # 可能的链接特征
    link_patterns = [
        {'text': '搜书吧', 'priority': 3},
        {'text': '进入论坛', 'priority': 2},
        {'text': '主站', 'priority': 1},
        {'text': '官网', 'priority': 1},
        {'url': 'soushu', 'priority': 3},
        {'url': 'shu', 'priority': 2},
        {'url': 'allshu', 'priority': 2}
    ]
    
    found_links = []
    for a in soup.find_all('a', href=True):
        href = a['href'].lower()
        text = a.text.strip().lower()
        
        for pattern in link_patterns:
            if 'text' in pattern and pattern['text'].lower() in text:
                found_links.append((pattern['priority'], a['href']))
            elif 'url' in pattern and pattern['url'] in href:
                found_links.append((pattern['priority'], a['href']))
    
    if found_links:
        # 按优先级排序
        found_links.sort(key=lambda x: x[0], reverse=True)
        return found_links[0][1]
    
    return None

class SouShuBaClient:
    def __init__(self, hostname: str, username: str, password: str, 
                 questionid: str = '0', answer: str = None,
                 proxies: dict = None):
        self.session = requests.Session()
        self.hostname = hostname
        self.username = username
        self.password = password
        self.questionid = questionid
        self.answer = answer
        self.proxies = proxies
        
        # 配置会话
        self.session.headers.update(DEFAULT_HEADERS)
        self.session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
        self.session.verify = False

    def get_formhash(self, url: str):
        """通用formhash获取方法"""
        for _ in range(3):  # 重试3次
            try:
                resp = self.session.get(url, timeout=15)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # 尝试多种方式获取formhash
                formhash = None
                for selector in [
                    'input[name="formhash"]',
                    'input[name^="formhash"]',
                    'input[value][name*="hash"]'
                ]:
                    element = soup.select_one(selector)
                    if element and element.get('value'):
                        formhash = element.get('value')
                        break
                
                if formhash:
                    return formhash
                
                logger.warning(f"未找到formhash，尝试备用方案: {url}")
                # 备用方案：从JS变量中提取
                script_tags = soup.find_all('script')
                for script in script_tags:
                    if script.string and 'formhash' in script.string:
                        match = re.search(r'formhash["\']?\s*[:=]\s*["\']?([a-f0-9]+)', script.string)
                        if match:
                            return match.group(1)
                
            except Exception as e:
                logger.warning(f"获取formhash失败: {e}")
                random_delay()
        
        raise ValueError(f"无法从 {url} 获取formhash")

    def login(self):
        """登录搜书吧"""
        try:
            # 第一步：获取登录页面
            login_url = f'https://{self.hostname}/member.php?mod=logging&action=login'
            loginhash, formhash = self._get_login_hashes(login_url)
            
            # 第二步：提交登录
            login_post_url = f'https://{self.hostname}/member.php?mod=logging&action=login&loginsubmit=yes' \
                            f'&loginhash={loginhash}&inajax=1'
            
            post_data = {
                'formhash': formhash,
                'referer': f'https://{self.hostname}/',
                'username': self.username,
                'password': self.password,
                'questionid': self.questionid,
                'answer': self.answer,
                'cookietime': '2592000'  # 记住登录30天
            }
            
            headers = deepcopy(DEFAULT_HEADERS)
            headers.update({
                'Origin': f'https://{self.hostname}',
                'Referer': login_url,
                'Content-Type': 'application/x-www-form-urlencoded'
            })
            
            response = self.session.post(
                login_post_url,
                data=post_data,
                headers=headers,
                timeout=15
            )
            
            # 验证登录结果
            if response.status_code != 200:
                raise ValueError(f"登录请求失败，状态码: {response.status_code}")
                
            if '欢迎您回来' in response.text or self.username in response.text:
                logger.info(f"登录成功: {self.username}")
                return True
            
            # 检查错误信息
            error_msg = self._parse_login_error(response.text)
            raise ValueError(f"登录失败: {error_msg or '未知错误'}")
            
        except Exception as e:
            logger.error(f"登录过程中出错: {e}")
            raise

    def _get_login_hashes(self, login_url):
        """获取登录所需的hash值"""
        response = self.session.get(login_url, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 获取loginhash
        loginhash = ''
        login_div = soup.find('div', id=re.compile(r'main_messaqge_'))
        if login_div:
            loginhash = login_div['id'].split('_')[-1]
        
        # 获取formhash
        formhash = self.get_formhash(login_url)
        
        return loginhash, formhash

    def _parse_login_error(self, html):
        """解析登录错误信息"""
        soup = BeautifulSoup(html, 'html.parser')
        error_div = soup.find('div', class_='alert_error')
        if error_div:
            return error_div.text.strip()
        return None

    def post_dynamic(self, message: str):
        """发布空间动态"""
        try:
            home_url = f'https://{self.hostname}/home.php'
            formhash = self.get_formhash(home_url)
            
            post_url = f'https://{self.hostname}/home.php?mod=spacecp&ac=doing&handlekey=doing&inajax=1'
            
            post_data = {
                'message': message.encode('gbk'),
                'addsubmit': 'true',
                'spacenote': 'true',
                'referer': home_url,
                'formhash': formhash
            }
            
            headers = deepcopy(DEFAULT_HEADERS)
            headers.update({
                'Origin': f'https://{self.hostname}',
                'Referer': home_url,
                'Content-Type': 'application/x-www-form-urlencoded'
            })
            
            response = self.session.post(
                post_url,
                data=post_data,
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 200 and '操作成功' in response.text:
                return True
            
            logger.warning(f"发布动态失败: {response.text[:200]}")
            return False
            
        except Exception as e:
            logger.error(f"发布动态时出错: {e}")
            return False

    def get_credit(self):
        """获取积分信息"""
        try:
            credit_url = f"https://{self.hostname}/home.php?mod=spacecp&ac=credit&showcredit=1&inajax=1"
            response = self.session.get(credit_url, timeout=15)
            
            # 解析XML格式的响应
            root = ET.fromstring(response.text)
            cdata = root.text
            
            # 从CDATA中提取积分
            soup = BeautifulSoup(cdata, 'html.parser')
            credit_span = soup.find('span', id='hcredit_2')
            if credit_span:
                return credit_span.text.strip()
            
            return "未知"
            
        except Exception as e:
            logger.error(f"获取积分时出错: {e}")
            return "获取失败"

def main():
    try:
        logger.info("="*50)
        logger.info("搜书吧自动任务开始")
        logger.info("="*50)
        
        # 步骤1：获取真实域名
        base_url = None
        initial_url = 'http://' + os.environ.get('SOUSHUBA_HOSTNAME', 'www.soushu2025.com')
        
        for _ in range(3):  # 最多尝试3次
            try:
                logger.info(f"尝试获取真实域名，初始URL: {initial_url}")
                
                # 获取第一层重定向
                redirect_url = get_final_url(initial_url)
                if not redirect_url or redirect_url == initial_url:
                    logger.warning("未获取到有效重定向")
                    continue
                
                logger.info(f"第一层重定向: {redirect_url}")
                random_delay(2, 5)
                
                # 获取第二层重定向
                final_url = get_final_url(redirect_url)
                if not final_url or final_url == redirect_url:
                    logger.warning("未获取到第二层重定向")
                    continue
                
                logger.info(f"最终重定向: {final_url}")
                
                # 解析真实域名
                parsed = urlparse(final_url)
                if not parsed.netloc:
                    continue
                    
                base_domain = parsed.netloc.split(':')[0]  # 去除端口
                base_url = f"https://{base_domain}"
                break
                
            except Exception as e:
                logger.warning(f"获取域名时出错: {e}")
                random_delay(5, 10)
        
        if not base_url:
            logger.error("无法获取搜书吧真实域名")
            return False
        
        logger.info(f"使用基础URL: {base_url}")
        hostname = urlparse(base_url).hostname
        
        # 步骤2：登录
        client = SouShuBaClient(
            hostname=hostname,
            username=os.environ.get('SOUSHUBA_USERNAME'),
            password=os.environ.get('SOUSHUBA_PASSWORD')
        )
        
        try:
            client.login()
        except Exception as e:
            logger.error(f"登录失败: {e}")
            return False
        
        # 步骤3：发布动态
        success_count = 0
        for i in range(5):  # 尝试发布5次动态
            try:
                message = f"每日签到赚银币 {i+1}/5"
                if client.post_dynamic(message):
                    success_count += 1
                    logger.info(f"动态发布成功 ({i+1}/5)")
                else:
                    logger.warning(f"动态发布失败 ({i+1}/5)")
                
                if i < 4:  # 最后一次不需要等待
                    delay = random.randint(60, 180)  # 1-3分钟随机延迟
                    logger.info(f"等待{delay}秒后继续...")
                    time.sleep(delay)
                    
            except Exception as e:
                logger.error(f"发布动态时出错: {e}")
        
        # 步骤4：获取积分
        credit = client.get_credit()
        logger.info(f"任务完成 - 成功发布动态: {success_count}次, 当前积分: {credit}")
        
        return success_count >= 3  # 至少成功3次视为成功
        
    except Exception as e:
        logger.exception("主程序运行出错")
        return False
    finally:
        logger.info("="*50)
        logger.info("搜书吧自动任务结束")
        logger.info("="*50)

if __name__ == '__main__':
    if main():
        sys.exit(0)
    else:
        sys.exit(1)
