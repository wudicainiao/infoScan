# coding:utf-8
import time
import pathlib

class define:
    stop_me = False

    ports = ['445','135','6379'] # 默认扫描端口
    payload_headers = {
    'User':"1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"}
    relative_directory = pathlib.Path(__file__).parent.parent  # 相对路径
    data_storage_dir = relative_directory.joinpath('data')  # 数据存放目录
    module_dir = relative_directory.joinpath('modules')
    request_ssl_verify = False
    request_timeout_second = 10

    GREEN       = "\033[32m"
    RED         = "\033[0;31m"
    BLUE        = "\033[94m"
    ORANGE      = "\033[33m"
    Timeout     = 500
    module_timeout = 10
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
    request_default_headers = {
    'Accept': 'text/html,application/xhtml+xml,'
              'application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
    'Cache-Control': 'max-age=0',
    'DNT': '1',
    'Referer': 'https://www.google.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Upgrade-Insecure-Requests': '1',
    'X-Forwarded-For': '127.0.0.1'
}
    enable_random_ua = True
