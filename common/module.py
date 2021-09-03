import os
import re
import sys
import time
import json
import socket
import random
import string
import platform
import subprocess
from urllib.parse import scheme_chars
from ipaddress import IPv4Address, ip_address
from distutils.version import LooseVersion
from pathlib import Path
from stat import S_IXUSR

import requests
import tenacity
from dns.resolver import Resolver

from lib.config import define

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) '
    'Gecko/20100101 Firefox/68.0',
    'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/68.0']

IP_RE = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')  # pylint: disable=line-too-long
SCHEME_RE = re.compile(r'^([' + scheme_chars + ']+:)?//')


def gen_fake_header():
    """
    Generate fake request headers
    """
    headers = define.request_default_headers.copy()
    if not isinstance(headers, dict):
        headers = dict()
    if define.enable_random_ua:
        ua = random.choice(user_agents)
        headers['User-Agent'] = ua
    headers['Accept-Encoding'] = 'gzip, deflate'
    return headers


def get_random_header():
    """
    Get random header
    """
    headers = gen_fake_header()
    if not isinstance(headers, dict):
        headers = None
    return headers


def get_random_proxy():
    """
    Get random proxy
    """
    try:
        return random.choice(define.request_proxy_pool)
    except IndexError:
        return None


def match_main_domain(domain):
    if not isinstance(domain, str):
        return None
    item = domain.lower().strip()
    return Domain(item).match()


def check_response(method, resp, module=None):
    """
    检查响应 输出非正常响应返回json的信息

    :param method: 请求方法
    :param resp: 响应体
    :return: 是否正常响应
    """
    if resp.status_code == 200 and resp.content:
        return True
    print('ALERT'+ f" Module Name: {module} status_code: {resp.status_code} - "
                        f'{resp.reason} {len(resp.content)}')
    return False


def mark_subdomain(old_data, now_data):
    """
    标记新增子域并返回新的数据集

    :param list old_data: 之前子域数据
    :param list now_data: 现在子域数据
    :return: 标记后的的子域数据
    :rtype: list
    """
    # 第一次收集子域的情况
    mark_data = now_data.copy()
    if not old_data:
        for index, item in enumerate(mark_data):
            item['new'] = 1
            mark_data[index] = item
        return mark_data
    # 非第一次收集子域的情况
    old_subdomains = {item.get('subdomain') for item in old_data}
    for index, item in enumerate(mark_data):
        subdomain = item.get('subdomain')
        if subdomain in old_subdomains:
            item['new'] = 0
        else:
            item['new'] = 1
        mark_data[index] = item
    return mark_data


@tenacity.retry(stop=tenacity.stop_after_attempt(3),
                wait=tenacity.wait_fixed(2))
def check_net():
    urls = ['http://ip-api.com/json/']
    url = random.choice(urls)
    header = {'User_Agent': 'curl'}
    timeout = define.request_timeout_second
    verify = define.request_ssl_verify
    logger.log('DEBUG', f'Trying to access {url}')
    session = requests.Session()
    session.trust_env = False
    try:
        rsp = session.get(url, headers=header, timeout=timeout, verify=verify)
    except Exception as e:
        logger.log('ERROR', e.args)
        logger.log('ALERT', 'Unable to access Internet, retrying...')
        raise e
    logger.log('DEBUG', 'Access to Internet OK')
    country = rsp.json().get('country').lower()
    if country in ['cn', 'china']:
        logger.log('DEBUG', f'The computer is located in China')
        return True, True
    else:
        logger.log('DEBUG', f'The computer is not located in China')
        return True, False


def match_subdomains(domain, html, distinct=True, fuzzy=True):
    """
    Use regexp to match subdomains

    :param  str domain: main domain
    :param  str html: response html text
    :param  bool distinct: deduplicate results or not (default True)
    :param  bool fuzzy: fuzzy match subdomain or not (default True)
    :return set/list: result set or list
    """
    if fuzzy:
        regexp = r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}' \
                 + domain.replace('.', r'\.')
        result = re.findall(regexp, html, re.I)
        if not result:
            return set()
        deal = map(lambda s: s.lower(), result)
        if distinct:
            return set(deal)
        else:
            return list(deal)
    else:
        regexp = r'(?:\>|\"|\'|\=|\,)(?:http\:\/\/|https\:\/\/)?' \
                 r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}' \
                 + domain.replace('.', r'\.')
        result = re.findall(regexp, html, re.I)
    if not result:
        return set()
    regexp = r'(?:http://|https://)'
    deal = map(lambda s: re.sub(regexp, '', s[1:].lower()), result)
    if distinct:
        return set(deal)
    else:
        return list(deal)
