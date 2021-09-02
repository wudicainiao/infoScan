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


def get_proxy():
    """
    Get proxy
    """
    if define.enable_request_proxy:
        return get_random_proxy()
    return None


def split_list(ls, size):
    """
    Split list

    :param list ls: list
    :param int size: size
    :return list: result

    >>> split_list([1, 2, 3, 4], 3)
    [[1, 2, 3], [4]]
    """
    if size == 0:
        return ls
    return [ls[i:i + size] for i in range(0, len(ls), size)]


def match_main_domain(domain):
    if not isinstance(domain, str):
        return None
    item = domain.lower().strip()
    return Domain(item).match()


def read_target_file(target):
    domains = list()
    with open(target, encoding='utf-8', errors='ignore') as file:
        for line in file:
            domain = match_main_domain(line)
            if not domain:
                continue
            domains.append(domain)
    sorted_domains = sorted(set(domains), key=domains.index)
    return sorted_domains


def get_from_target(target):
    domains = set()
    if isinstance(target, str):
        if target.endswith('.txt'):
            logger.log('FATAL', 'Use targets parameter for multiple domain names')
            exit(1)
        domain = match_main_domain(target)
        if not domain:
            return domains
        domains.add(domain)
    return domains


def get_from_targets(targets):
    domains = set()
    if not isinstance(targets, str):
        return domains
    try:
        path = Path(targets)
    except Exception as e:
        logger.log('ERROR', e.args)
        return domains
    if path.exists() and path.is_file():
        domains = read_target_file(targets)
        return domains
    return domains


def get_domains(target, targets=None):
    logger.log('DEBUG', f'Getting domains')
    target_domains = get_from_target(target)
    targets_domains = get_from_targets(targets)
    domains = list(target_domains.union(targets_domains))
    if targets_domains:
        domains = sorted(domains, key=targets_domains.index)  # 按照targets原本的index排序
    if not domains:
        logger.log('ERROR', f'Did not get a valid domain name')
    logger.log('DEBUG', f'The obtained domains \n{domains}')
    return domains


def check_dir(dir_path):
    if not dir_path.exists():
        logger.log('INFOR', f'{dir_path} does not exist, directory will be created')
        dir_path.mkdir(parents=True, exist_ok=True)


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


def remove_invalid_string(string):
    # Excel文件中单元格值不能直接存储以下非法字符
    return re.sub(r'[\000-\010]|[\013-\014]|[\016-\037]', r'', string)

def get_timestamp():
    return int(time.time())


def get_timestring():
    return time.strftime('%Y%m%d_%H%M%S', time.localtime(time.time()))


def get_classname(classobj):
    return classobj.__class__.__name__


def python_version():
    return sys.version


def calc_alive(data):
    return len(list(filter(lambda item: item.get('alive') == 1, data)))


def count_alive(name):
    db = Database()
    result = db.count_alive(name)
    count = result.scalar()
    db.close()
    return count


def get_subdomains(data):
    return set(map(lambda item: item.get('subdomain'), data))


def set_id_none(data):
    new_data = []
    for item in data:
        item['id'] = None
        new_data.append(item)
    return new_data


def get_filtered_data(data):
    filtered_data = []
    for item in data:
        resolve = item.get('resolve')
        if resolve != 1:
            filtered_data.append(item)
    return filtered_data


def get_sample_banner(headers):
    temp_list = []
    server = headers.get('Server')
    if server:
        temp_list.append(server)
    via = headers.get('Via')
    if via:
        temp_list.append(via)
    power = headers.get('X-Powered-By')
    if power:
        temp_list.append(power)
    banner = ','.join(temp_list)
    return banner


def check_ip_public(ip_list):
    for ip_str in ip_list:
        ip = ip_address(ip_str)
        if not ip.is_global:
            return 0
    return 1


def ip_is_public(ip_str):
    ip = ip_address(ip_str)
    if not ip.is_global:
        return 0
    return 1


def get_request_count():
    return os.cpu_count() * 16


def uniq_dict_list(dict_list):
    return list(filter(lambda name: dict_list.count(name) == 1, dict_list))


def delete_file(*paths):
    for path in paths:
        try:
            path.unlink()
        except Exception as e:
            logger.log('ERROR', e.args)


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


def check_dep():
    logger.log('INFOR', 'Checking dependent environment')
    implementation = platform.python_implementation()
    version = platform.python_version()
    if implementation != 'CPython':
        logger.log('FATAL', f'OneForAll only passed the test under CPython')
        exit(1)
    if LooseVersion(version) < LooseVersion('3.6'):
        logger.log('FATAL', 'OneForAll requires Python 3.6 or higher')
        exit(1)


def get_net_env():
    logger.log('INFOR', 'Checking network environment')
    try:
        result = check_net()
    except Exception as e:
        logger.log('DEBUG', e.args)
        logger.log('ALERT', 'Please check your network environment.')
        return False, None
    return result


def get_main_domain(domain):
    if not isinstance(domain, str):
        return None
    return Domain(domain).registered()


def call_massdns(massdns_path, dict_path, ns_path, output_path, log_path,
                 query_type='A', process_num=1, concurrent_num=10000,
                 quiet_mode=False):
    logger.log('DEBUG', 'Start running massdns')
    quiet = ''
    if quiet_mode:
        quiet = '--quiet'
    status_format = define.brute_status_format
    socket_num = define.brute_socket_num
    resolve_num = define.brute_resolve_num
    cmd = f'{massdns_path} {quiet} --status-format {status_format} ' \
          f'--processes {process_num} --socket-count {socket_num} ' \
          f'--hashmap-size {concurrent_num} --resolvers {ns_path} ' \
          f'--resolve-count {resolve_num} --type {query_type} ' \
          f'--flush --output J --outfile {output_path} ' \
          f'--root --error-log {log_path} {dict_path} --filter OK ' \
          f'--sndbuf 0 --rcvbuf 0'
    logger.log('DEBUG', f'Run command {cmd}')
    subprocess.run(args=cmd, shell=True)
    logger.log('DEBUG', f'Finished massdns')


def is_subname(name):
    chars = string.ascii_lowercase + string.digits + '.-'
    for char in name:
        if char not in chars:
            return False
    return True


def ip_to_int(ip):
    if isinstance(ip, int):
        return ip
    try:
        ipv4 = IPv4Address(ip)
    except Exception as e:
        logger.log('ERROR', e.args)
        return 0
    return int(ipv4)


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


def check_random_subdomain(subdomains):
    if not subdomains:
        logger.log('ALERT', f'The generated dictionary is empty')
        return
    for subdomain in subdomains:
        if subdomain:
            logger.log('ALERT', f'Please check whether {subdomain} is correct or not')
            return


def get_url_resp(url):
    logger.log('INFOR', f'Attempting to request {url}')
    timeout = define.request_timeout_second
    verify = define.request_ssl_verify
    session = requests.Session()
    session.trust_env = False
    try:
        resp = session.get(url, params=None, timeout=timeout, verify=verify)
    except Exception as e:
        logger.log('ALERT', f'Error request {url}')
        logger.log('DEBUG', e.args)
        return None
    return resp


def decode_resp_text(resp):
    content = resp.content
    if not content:
        return str('')
    try:
        # 先尝试用utf-8严格解码
        content = str(content, encoding='utf-8', errors='strict')
    except (LookupError, TypeError, UnicodeError):
        try:
            # 再尝试用gb18030严格解码
            content = str(content, encoding='gb18030', errors='strict')
        except (LookupError, TypeError, UnicodeError):
            # 最后尝试自动解码
            content = str(content, errors='replace')
    return content


def sort_by_subdomain(data):
    return sorted(data, key=lambda item: item.get('subdomain'))


def looks_like_ip(maybe_ip):
    """Does the given str look like an IP address?"""
    if not maybe_ip[0].isdigit():
        return False

    try:
        socket.inet_aton(maybe_ip)
        return True
    except (AttributeError, UnicodeError):
        if IP_RE.match(maybe_ip):
            return True
    except socket.error:
        return False

