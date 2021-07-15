# -*- encoding: utf-8 -*-
# by dacA1niao

import os
import sys
import time
import queue
import gevent
import threading
import grequests
import multiprocessing
from urllib.parse import urlparse
from lib.config import define
from lib.check_cdn import iscdn
from lib.ipasn import IPAsnInfo
from lib.ipreg import IpRegData
from lib.report import report
from lib.common import creat_xlsx,scan_given_ports,is_port_open
from gevent import socket as g_socket

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
            target = {'scheme': None, 'host': url, 'port': None,
                'ip':ip, 'ports_open': None}
            q_targets.put(target)
        except Exception as e:
            q_results.put('Invalid domain error: %s' % e)

def check_cdn(q_targets, q_targets_ex, q_results, threads = 6):
    try:
        all_threads = []
        for i in range(threads):
            t = threading.Thread(target=iscdn, args=(q_targets, q_targets_ex, q_results))
            t.start()
            all_threads.append(t)
        for t in all_threads:
            t.join()
        q_results.put('ip info data search All done')
    except Exception as e:
        q_results.put('Invalid cdn threads')

def check_waf(q_targets, queue_targets_origin, q_results):
    while True:
        try:
            target = queue_targets_origin.get_nowait()
        except queue.Empty:
            break

def ports_open(q_targets,queue_targets_origin, q_results):
    while True:
        try:
            target = queue_targets_origin.get_nowait()
        except queue.Empty:
            break

        url = target['host']
        if url.find('://') < 0:
            scheme = 'unknown'
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
        if scheme == 'unknown':
            scheme = []
            scheme.append('https://')
            scheme.append('http://')

        if port:
            scan_given_ports(host, ports_open, port)
            if ports_open and type(scheme) == list:
                url = []
                for sch in scheme:
                    url.append(sch+host+':'+str(port))
                target['url'] = url
                target['ports_open'] = ports_open
                q_targets.put(target)
            elif ports_open:
                target['url'] = scheme+'://'+host+':'+str(port)
                target['ports_open'] = ports_open
                q_targets.put(target)
            elif not ports_open:
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
            scan_given_ports(host, ports_open)
            if ports_open:
                if port_open_80 and port_open_443:
                    url = []
                    url.append('http://'+host+':80')
                    url.append('https://'+host+':443')
                    target['ports_open'] = ports_open
                    target['url'] = url
                    q_targets.put(target)
                if port_open_80:
                    target['url'] = 'http://'+host+':80'
                    target['ports_open'] = ports_open
                    q_targets.put(target)
                elif port_open_443:
                    target['url'] = 'https://'+host+':443'
                    target['ports_open'] = ports_open
                    q_targets.put(target)
            else:
                target['url'] = 'Time out'
                target['ports_open'] = 'Time out'
                q_targets.put(target)



def prepare_fofa_target(target_list, q_targets, q_results):
    ## 该函数负责最终将处理完的target_list生成标准格式json加入q_targets以进行下一步扫描
    ## 需要判断存活,file文件读取的通过db读取归属地
    ## 从文件读取的
    pass


def prepare_file_target(target_list, q_targets, q_targets_ex, q_results):
    ## 该函数负责最终将处理完的target_list生成标准格式json加入q_targets以进行下一步扫描
    ## 需要判断存活,file文件读取的通过db读取归属地
    ## 从文件读取的

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

    ## {'scheme': None, 'host': 'https://mayfaircyprus.com/', 'port': None, 'ip': '104.21.78.238', 'ports_open': None, 'cidr': '104.21.0.0/16', 'asn': '13335', 'org': 'CLOUDFLARENET', 'addr': '美国', 'isp': '未知', 'cdn': 'exist'}
    ## cdn查询
    check_cdn(q_targets, queue_targets_origin, q_results)

    ## {'scheme': None, 'host': 'https://wiki.ioin.in/', 'port': None, 'ip': '128.1.135.62', 'ports_open': {443}, 'cidr': '128.1.135.0/24', 'asn': '135377', 'org': 'UCloud (HK) Holdings Group Limited', 'addr': '中国香港', 'isp': '层峰网络', 'cdn': 'may be real ip', 'url': 'https://wiki.ioin.in:443'}
    ## portscan 
    q_results.put('start ports scan')
    threads = [gevent.spawn(ports_open,
                        q_targets,queue_targets_origin, q_results) for _ in range(1000)]
    gevent.joinall(threads)

    #while True:
    #    try:
    #        print(q_targets.get(timeout=0.2))
    #    except queue.Empty:
    #        break
    ## waf 探测
    #check_waf(queue_targets_origin, q_targets, q_results)
    threads = [gevent.spawn(check_waf,
                        q_targets,queue_targets_origin, q_results) for _ in range(500)]
    gevent.joinall(threads)
    # check_waf(q_targets, q_targets_ex, q_results)



    # target = {'scheme': None, 'host': target.strip(), 'port': None,
    #            'ip':None, 'ports_open': None}


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
        #creat_xlsx()
        q_results.put('excel file created.')
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


        #p = multiprocessing.Process(
        #    target=prepare_targets,
        #    args=(target_list, q_targets, q_results, args, tasks_count, process_targets_done))
        #p.daemon = True
        #p.start()
        #time.sleep(1.0)  # 让prepare_targets进程尽快开始执行

    if sys.argv[1] == '--fofa':
        pass
    q_results.put('scan all done')
    ## 关闭管理标准输出的线程
    define.stop_me = True
