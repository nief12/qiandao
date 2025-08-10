# -*- coding: utf-8 -*-
"""
实现搜书吧论坛登入和发布空间动态
"""
import os
import re
import sys
from copy import copy

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
import time
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

ch = logging.StreamHandler(stream=sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)

def get_refresh_url(url: str):
    try:
        logger.debug(f"获取重定向URL: {url}")
        response = requests.get(url, verify=False, timeout=30)
        if response.status_code != 403 and response.status_code != 200:
            response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        meta_tags = soup.find_all('meta', {'http-equiv': 'refresh'})

        if meta_tags:
            content = meta_tags[0].get('content', '')
            if 'url=' in content:
                redirect_url = content.split('url=')[1].strip()
                logger.info(f"重定向到: {redirect_url}")
                return redirect_url
        else:
            logger.warning("未找到meta刷新标签")
            return None
    except Exception as e:
        logger.error(f'获取重定向URL时出错: {e}')
        return None

def get_url(url: str):
    try:
        logger.debug(f"解析搜书吧链接: {url}")
        resp = requests.get(url, verify=False, timeout=30)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.content, 'html.parser')

        # 查找所有可能的链接模式
        possible_links = soup.find_all('a', href=True)
        for link in possible_links:
            if "搜书吧" in link.text.strip():
                logger.info(f"找到搜书吧链接: {link['href']}")
                return link['href']
        
        # 备用搜索方式
        for link in possible_links:
            if "soushu" in link['href'].lower() or "shu" in link['href'].lower():
                logger.info(f"通过URL模式找到链接: {link['href']}")
                return link['href']
                
        logger.warning("未找到搜书吧链接")
        logger.debug(f"页面标题: {soup.title.string if soup.title else '无标题'}")
        return None
    except Exception as e:
        logger.error(f'解析搜书吧链接时出错: {e}')
        return None

class SouShuBaClient:

    def __init__(self, hostname: str, username: str, password: str, questionid: str = '0', answer: str = None,
                 proxies: dict | None = None):
        self.session: requests.Session = requests.Session()
        self.hostname = hostname
        self.username = username
        self.password = password
        self.questionid = questionid
        self.answer = answer
        self._common_headers = {
            "Host": f"{ hostname }",
            "Connection": "keep-alive",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept-Language": "zh-CN,cn;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self.proxies = proxies
        # 添加重试机制
        self.session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))

    def login_form_hash(self):
        try:
            logger.debug("获取登录表单哈希")
            url = f'https://{self.hostname}/member.php?mod=logging&action=login'
            response = self.session.get(url, verify=False, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找loginhash
            loginhash_div = soup.find('div', id=re.compile(r'main_messaqge_'))
            if loginhash_div:
                loginhash = loginhash_div['id'].split('_')[-1]
            else:
                loginhash = ""
                logger.warning("未找到loginhash，使用空值")
            
            # 查找formhash
            formhash_input = soup.find('input', {'name': 'formhash'})
            if formhash_input and formhash_input.get('value'):
                formhash = formhash_input['value']
            else:
                # 备选方案
                for selector in ['input[name="formhash"]', 'input[name^="formhash"]']:
                    element = soup.select_one(selector)
                    if element and element.get('value'):
                        formhash = element.get('value')
                        break
                else:
                    logger.error("未找到formhash")
                    raise ValueError("无法获取登录表单的formhash")
            
            logger.debug(f"获取到loginhash: {loginhash}, formhash: {formhash}")
            return loginhash, formhash
        except Exception as e:
            logger.exception("获取登录表单哈希时出错")
            raise

    def login(self):
        """Login with username and password"""
        try:
            loginhash, formhash = self.login_form_hash()
            login_url = f'https://{self.hostname}/member.php?mod=logging&action=login&loginsubmit=yes' \
                        f'&handlekey=register&loginhash={loginhash}&inajax=1'

            headers = copy(self._common_headers)
            headers["origin"] = f'https://{self.hostname}'
            headers["referer"] = f'https://{self.hostname}/member.php?mod=logging&action=login'
            
            payload = {
                'formhash': formhash,
                'referer': f'https://{self.hostname}/',
                'username': self.username,
                'password': self.password,
                'questionid': self.questionid,
                'answer': self.answer
            }

            logger.debug(f"登录请求: {login_url}")
            resp = self.session.post(login_url, proxies=self.proxies, data=payload, headers=headers, 
                                    verify=False, timeout=30)
            
            # 检查登录是否成功
            if resp.status_code == 200:
                success_patterns = [
                    f'欢迎您回来，{self.username}',
                    '登录成功',
                    '现在将转入登录前页面',
                    '登录成功'
                ]
                
                if any(pattern in resp.text for pattern in success_patterns):
                    logger.info(f'欢迎 {self.username}! 登录成功')
                else:
                    logger.error("登录失败: 响应中未找到成功标识")
                    logger.debug(f"登录响应内容: {resp.text[:500]}...")
                    raise ValueError('登录失败，请检查用户名和密码!')
            else:
                logger.error(f"登录请求失败，状态码: {resp.status_code}")
                resp.raise_for_status()
                
        except Exception as e:
            logger.exception("登录过程中出错")
            raise

    def credit(self):
        try:
            credit_url = f"https://{self.hostname}/home.php?mod=spacecp&ac=credit&showcredit=1&inajax=1&ajaxtarget=extcreditmenu_menu"
            logger.debug(f"获取积分信息: {credit_url}")
            credit_rst = self.session.get(credit_url, verify=False, timeout=30).text

            # 解析 XML，提取 CDATA
            root = ET.fromstring(credit_rst)
            cdata_content = root.text

            # 使用 BeautifulSoup 解析 CDATA 内容
            cdata_soup = BeautifulSoup(cdata_content, "html.parser")
            hcredit_2 = cdata_soup.find("span", id="hcredit_2")
            
            if hcredit_2 and hcredit_2.string:
                return hcredit_2.string.strip()
            else:
                logger.warning("未找到积分信息")
                return "未知"
        except Exception as e:
            logger.error(f"获取积分时出错: {e}")
            return "获取失败"

    def space_form_hash(self):
        try:
            url = f'https://{self.hostname}/home.php'
            logger.debug(f"访问主页获取formhash: {url}")
            response = self.session.get(url, verify=False, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 尝试多种方式查找formhash
            formhash_input = soup.find('input', {'name': 'formhash'})
            if formhash_input:
                formhash = formhash_input.get('value')
                if formhash:
                    logger.debug(f"找到formhash: {formhash}")
                    return formhash
            
            # 备选选择器
            for selector in ['input[name="formhash"]', 'input[name^="formhash"]']:
                element = soup.select_one(selector)
                if element and element.get('value'):
                    formhash = element.get('value')
                    logger.debug(f"通过选择器 '{selector}' 找到formhash: {formhash}")
                    return formhash
            
            # 记录HTML片段用于调试
            logger.error("无法在页面中找到formhash")
            logger.debug(f"页面标题: {soup.title.string if soup.title else '无标题'}")
            logger.debug(f"HTML片段: {response.text[:1000]}")
            raise ValueError("无法获取formhash")
        except Exception as e:
            logger.exception(f"获取formhash时发生错误: {e}")
            raise

    def space(self):
        try:
            formhash = self.space_form_hash()
            space_url = f"https://{self.hostname}/home.php?mod=spacecp&ac=doing&handlekey=doing&inajax=1"
            logger.info(f"准备发布空间动态，formhash: {formhash}")

            headers = copy(self._common_headers)
            headers["origin"] = f'https://{self.hostname}'
            headers["referer"] = f'https://{self.hostname}/home.php'

            success_count = 0
            for x in range(5):
                try:
                    message = f"开心赚银币 {x + 1} 次"
                    payload = {
                        "message": message.encode("GBK"),
                        "addsubmit": "true",
                        "spacenote": "true",
                        "referer": "home.php",
                        "formhash": formhash
                    }
                    
                    logger.debug(f"发布动态 {x+1}: {message}")
                    resp = self.session.post(space_url, proxies=self.proxies, data=payload, 
                                            headers=headers, verify=False, timeout=30)
                    
                    if resp.status_code == 200 and "操作成功" in resp.text:
                        logger.info(f'{self.username} 第 {x + 1} 次发布成功!')
                        success_count += 1
                    else:
                        logger.warning(f'{self.username} 第 {x + 1} 次发布失败! 响应: {resp.status_code}')
                        logger.debug(f"失败响应内容: {resp.text[:200]}...")
                    
                    # 即使失败也等待
                    if x < 4:
                        logger.info("等待120秒后进行下一次发布...")
                        time.sleep(120)
                        
                except Exception as e:
                    logger.error(f"第 {x+1} 次发布时出错: {e}")
            
            return success_count
        except Exception as e:
            logger.exception("发布空间动态时出错")
            return 0


if __name__ == '__main__':
    try:
        logger.info("="*50)
        logger.info("搜书吧自动任务开始")
        logger.info("="*50)
        
        # 第一步：获取初始重定向
        initial_url = 'http://' + os.environ.get('SOUSHUBA_HOSTNAME', 'www.soushu2025.com')
        logger.info(f"初始URL: {initial_url}")
        redirect_url = get_refresh_url(initial_url)
        
        if not redirect_url:
            logger.error("未获取到重定向URL，退出")
            sys.exit(1)
        
        # 第二步：获取第二次重定向
        time.sleep(2)
        logger.info(f"第二级重定向URL: {redirect_url}")
        redirect_url2 = get_refresh_url(redirect_url)
        
        if not redirect_url2:
            logger.error("未获取到第二级重定向URL，退出")
            sys.exit(1)
        
        # 第三步：解析搜书吧真实URL
        time.sleep(2)
        logger.info(f"解析真实URL: {redirect_url2}")
        url = get_url(redirect_url2)
        
        if not url:
            logger.error("未找到搜书吧链接，退出")
            sys.exit(1)
        
        # 解析主机名
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        logger.info(f"解析到主机名: {hostname}")
        
        # 创建客户端
        client = SouShuBaClient(
            hostname,
            os.environ.get('SOUSHUBA_USERNAME', "libesse"),
            os.environ.get('SOUSHUBA_PASSWORD', "yF9pnSBLH3wpnLd")
        )
        
        # 登录
        client.login()
        
        # 发布动态
        success_count = client.space()
        
        # 查询积分
        credit = client.credit()
        logger.info(f"{client.username} 成功发布 {success_count} 条动态，当前积分: {credit}")
        
        if success_count < 3:
            logger.warning("成功发布动态少于3条，可能存在问题")
            sys.exit(1)
        else:
            logger.info("任务执行成功")
            sys.exit(0)
            
    except Exception as e:
        logger.exception("主程序运行出错")
        sys.exit(1)
