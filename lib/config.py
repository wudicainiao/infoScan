# coding:utf-8
import time
import pathlib

class define:
    stop_me = False

    ports = ['445','135','6379'] # 默认扫描端口
    proxies = {"http": "http://127.0.0.1:1080","https": "https://127.0.0.1:1080"} ## socks5 代理
    payload_headers = {
    'User':"1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"}
    relative_directory = pathlib.Path(__file__).parent.parent  # 相对路径
    data_storage_dir = relative_directory.joinpath('data')  # 数据存放目录


    GREEN       = "\033[32m"
    RED         = "\033[0;31m"
    BLUE        = "\033[94m"
    ORANGE      = "\033[33m"
    Timeout     = 500
    filename    = 'out\\%s.xlsx' % time.strftime("%Y-%m-%d-%H-%M", time.localtime(time.time()))

    banner = '''

                       __..--.._
  .....              .--~  .....  `.
.":    "`-..  .    .' ..-'"    :". `
` `._ ` _.'`"(     `-"'`._ ' _.' '
     ~~~      `.          ~~~
              .'
             /
            (
             ^---'

[*] Author:dacAIniao@重明安全
    '''

    usage = '''
Usage: 
    python3 infoScan.py [options]

Options:
    -f  ip_domain_file        eg : python3 infoScan.py -f url_ip.txt
'''

