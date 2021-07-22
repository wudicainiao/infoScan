# -*- encoding: utf-8 -*-
# by dacA1niao

import os
import re
import sys
import time
import queue
import gevent
import socket
import difflib
import requests
import threading
import multiprocessing
from urllib.parse import urlparse
from lib.config import define
from lib.check_cdn import iscdn
from lib.ipasn import IPAsnInfo
from lib.ipreg import IpRegData
from lib.report import report
from lib.common import creat_xlsx,write_xlsx,scan_given_ports,is_port_open
from gevent import socket as g_socket
import urllib3
urllib3.disable_warnings()

def domain_lookup_check(queue_targets_origin, q_targets, q_results):
    """
    解析域名，检查域名有效性
    """
    while True:
        try:
            url = queue_targets_origin.get_nowait()## 非阻塞式的从genvent queue(队列)中读取一个值
        except queue.Empty:
            break
        # scheme netloc path
        if url.find('://') < 0:
            netloc = url[:url.find('/')] if url.find('/') > 0 else url
        else:
            scheme, netloc, path, params, query, fragment = urlparse(url, 'http')

        # host port
        if netloc.find(':') >= 0:
            _ = netloc.split(':')
            host = _[0]
        else:
            host = netloc

        try:
            ip = g_socket.gethostbyname(host)
            target = {'host': url,
                'ip':ip, 'ports_open': None}
            q_targets.put(target)
        except Exception as e:
            q_results.put('[*]Invalid domain error: %s host : %s' %(e,url))

def check_cdn(q_targets, q_targets_ex, q_results, threads = 6):
    try:
        all_threads = []
        for i in range(threads):
            t = threading.Thread(target=iscdn, args=(q_targets, q_targets_ex, q_results))
            t.start()
            all_threads.append(t)
        for t in all_threads:
            t.join()
        q_results.put('[*]ip info data search All done')
    except Exception as e:
        q_results.put('[*]Invalid cdn threads')

def check_alive(q_targets, q_targets_ex, q_results, check_waf=False, threads = 50):
    try:
        all_threads = []
        for i in range(threads):
            if check_waf:
                t = threading.Thread(target=waf, args=(q_targets, q_targets_ex, q_results, check_waf))
            else:
                t = threading.Thread(target=alive, args=(q_targets, q_targets_ex, q_results, check_waf))
            t.start()
            all_threads.append(t)
        for t in all_threads:
            t.join()
        if check_waf:
            q_results.put('[*]waf test done')
        else:
            q_results.put('[*]alive test done')
    except Exception as e:
        q_results.put('[*]Invalid check_alive threads')


def alive(q_targets, q_targets_ex, q_results, check_waf):
    while True:
        try:
            target = q_targets.get_nowait()
        except queue.Empty:
            break
        template ={}
        title ={}
        if type(target['url']) == list:
            url = []
            for u in target['url']:
                try:
                    rs = requests.get(u, verify=False, allow_redirects=False, timeout=5, proxies = define.proxies)# proxies = define.proxies
                    url.append(u)
                    template[u] = rs.text
                    titles = re.findall(r"<title.*?>(.+?)</title>", rs.text)
                    if titles:
                        title[u] = titles
                    else:
                        title[u] = '未识别title'
                except socket.timeout:
                    pass
                except urllib3.exceptions.MaxRetryError:
                    pass
                except requests.exceptions.SSLError:
                    pass
                except requests.exceptions.ProxyError:
                    q_results.put('[*]please check lib/config.py proxies')
                except:
                    pass
            target['title'] = title if title else None
            target['url'] = url if url else None
            target['template'] = template if url else None
            q_targets_ex.put(target)
        else:
            try:
                if 'Time out' in target['url']:
                    target['title'] = None
                    target['url'] = None
                    target['template'] = None
                    q_targets_ex.put(target)
                    continue
                rs = requests.get(target['url'], verify=False, allow_redirects=False, timeout=5, proxies = define.proxies)
                template[target['url']] = rs.text

                titles = re.findall(r"<title.*?>(.+?)</title>", rs.text)
                if titles:
                    title[target['url']] = titles
                else:
                    title[target['url']] = '未识别title'

                target['title'] = title
                target['url'] = target['url']
                target['template'] = template
                q_targets_ex.put(target)
            except socket.timeout:
                target['title'] = None
                target['url'] = None
                target['template'] = None
                q_targets_ex.put(target)
            except urllib3.exceptions.MaxRetryError:
                target['title'] = None
                target['url'] = None
                target['template'] = None
                q_targets_ex.put(target)
            except requests.exceptions.SSLError:
                target['title'] = None
                target['url'] = None
                target['template'] = None
                q_targets_ex.put(target)
            except requests.exceptions.ProxyError:
                q_results.put('[*]please check lib/config.py proxies')
                target['title'] = None
                target['url'] = None
                target['template'] = None
                q_targets_ex.put(target)
            except:
                target['title'] = None
                target['url'] = None
                target['template'] = None
                q_targets_ex.put(target)

def waf(q_targets, q_targets_ex, q_results, check_waf):
    while True:
        try:
            target = q_targets_ex.get_nowait()
        except queue.Empty:
            break
        waf = {}
        # target['template'] type(dict) url:template 
        if target['template']:
            for u in target['template'].keys():
                try:
                    rs = requests.get(u, verify=False, headers=define.payload_headers, allow_redirects=False, timeout=5, proxies=define.proxies)
                    if round(difflib.SequenceMatcher(None, target['template'][u], rs.text).quick_ratio(),3) < 0.5:
                        waf[u] = 'True'
                    else:
                        waf[u] = 'False'
                except socket.timeout:
                    pass
                except urllib3.exceptions.MaxRetryError:
                    pass
                except requests.exceptions.SSLError:
                    pass
                except requests.exceptions.ProxyError:
                    q_results.put('[*]please check lib/config.py proxies')
                except Exception as e:
                    waf[u] = 'True'
                    target['template'] = None
                    target['waf'] = waf
                    q_targets.put(target)
                    q_results.put('[*]send payloads error exist waf %s' %u)
                    continue
            target['template'] = None
            target['waf'] = waf if waf else None
            q_targets.put(target)
        else:
            target['template'] = None
            target['waf'] = waf if waf else None
            q_targets.put(target)

def ports_open(q_targets,queue_targets_origin, q_results):
    while True:
        try:
            target = queue_targets_origin.get_nowait()
        except queue.Empty:
            break

        url = target['host']
        if url.find('://') < 0:
            scheme = None
            netloc = url[:url.find('/')] if url.find('/') > 0 else url
            path = ''
        else:
            scheme, netloc, path, params, query, fragment = urlparse(url, 'http')

        if netloc.find(':') >= 0:
            _ = netloc.split(':')
            host = _[0]
            port = int(_[1])
        else:
            host = netloc
            port = None

        if scheme == 'https' and port is None:
            port = 443
        elif scheme == 'http' and port is None:
            port = 80

        ports_open = set()

        ## 存在一种情况类似 127.0.0.1:1089 不会指定scheme
        if not scheme:
            scheme = []
            scheme.append('https://')
            scheme.append('http://')

        scan_given_ports(host, ports_open, port)

        # 127.0.0.1 127.0.0.1:8888 http://127.0.0.1 http://127.0.0.1:8080
        if port:
            if int(port) == 80:
                url = []
                url.append('http://'+host+':80')
                url.append('https://'+host+':443')
                target['ports_open'] = ports_open
                target['url'] = url
                q_targets.put(target)
                continue
            elif int(port) == 443:
                url = []
                url.append('http://'+host+':80')
                url.append('https://'+host+':443')
                target['ports_open'] = ports_open
                target['url'] = url
                q_targets.put(target)
                continue
            if ports_open and type(scheme) == list:
                url = []
                for sch in scheme:
                    url.append(sch+'://'+host+':'+str(port))
                target['url'] = url
                target['ports_open'] = ports_open
                q_targets.put(target)
            elif ports_open and scheme:
                #print('open host %s ports_open %s'%(host,ports_open))
                target['url'] = scheme+'://'+host+':'+str(port)
                target['ports_open'] = ports_open
                q_targets.put(target)
            elif ports_open:
                if type(ports_open) == list:
                    q_results.put('ports_open is list')
                target['url'] = scheme+'://'+host+':'+str(port)
                target['ports_open'] = ports_open
                q_targets.put(target)
            else:
                #print('close host %s ports_open %s'%(host,ports_open))
                target['url'] = 'Time out'
                target['ports_open'] = 'Time out'
                q_targets.put(target)
        else:
            port_open_80 = is_port_open(host, 80)
            port_open_443 = is_port_open(host, 443)
            if port_open_80:
                ports_open.add('80')
            elif port_open_443:
                ports_open.add('443')
            if ports_open:
                if port_open_80 and port_open_443:
                    url = []
                    url.append('http://'+host+':80')
                    url.append('https://'+host+':443')
                    target['ports_open'] = ports_open
                    target['url'] = url
                    q_targets.put(target)
                if port_open_80:
                    url = []
                    url.append('http://'+host+':80')
                    url.append('https://'+host+':443')
                    target['url'] = url
                    target['ports_open'] = ports_open
                    q_targets.put(target)
                elif port_open_443:
                    url = []
                    url.append('http://'+host+':80')
                    url.append('https://'+host+':443')
                    target['url'] = url
                    target['ports_open'] = ports_open
                    q_targets.put(target)
            else:
                target['url'] = 'Time out'
                target['ports_open'] = 'Time out'
                q_targets.put(target)



def prepare_fofa_target(target_list, q_targets, q_results):
    pass


def prepare_file_target(target_list, q_targets, q_targets_ex, q_results):
    from gevent.queue import Queue
    queue_targets_origin = Queue()

    for target in target_list:
        queue_targets_origin.put(target.strip())

    ## 域名有效性判断，域名解析
    threads = [gevent.spawn(domain_lookup_check,
                            queue_targets_origin,q_targets, q_results) for _ in range(500)]
    gevent.joinall(threads)

    ## asn等信息查询
    ipasn = IPAsnInfo()
    ipasn.run(q_targets, q_targets_ex)

    ## reg信息查询
    ipreg = IpRegData()
    ipreg.run(q_targets, q_targets_ex)

    ## cdn查询
    check_cdn(q_targets, queue_targets_origin, q_results)

    ## portscan 
    q_results.put('[*]start ports scan')
    threads = [gevent.spawn(ports_open,
                        q_targets,queue_targets_origin, q_results) for _ in range(1000)]
    gevent.joinall(threads)

    # 检测存活
    check_alive(q_targets, q_targets_ex, q_results)

    #检测waf
    check_alive(q_targets, q_targets_ex, q_results, check_waf=True)


if __name__ == '__main__':
    print(define.ORANGE+define.banner)
    
    q_targets = multiprocessing.Manager().Queue()    ## 用于在进程间进行队列通信
    q_targets_ex = multiprocessing.Manager().Queue()    ## 用于在进程间进行队列通信
    q_results = multiprocessing.Manager().Queue()    ## 用于在进程间进行队列通信

    ## 管理标准输出
    threading.Thread(target=report, args=(q_results,)).start()

    if len(sys.argv) < 2:
        print(define.ORANGE+define.usage)
        define.stop_me = True
        exit(-1)

    if sys.argv[1] == '--file':
        creat_xlsx(q_results)
        with open(sys.argv[2]) as inputfile:
            target_list = inputfile.readlines()
            ## 独立进程中使用gvent
            p = multiprocessing.Process(
                target=prepare_file_target,
                args=(target_list, q_targets, q_targets_ex, q_results))
            p.daemon = True
            p.start()
            p.join()
            time.sleep(1.0)  # 让prepare_targets进程尽快开始执行
        write_xlsx(q_targets, q_results)

    if sys.argv[1] == '--fofa':
        pass
    q_results.put('[*]scan all done')
    ## 关闭管理标准输出的线程
    define.stop_me = True
