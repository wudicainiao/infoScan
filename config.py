# coding:utf-8
import time
import pathlib

class define:
    stop_me = False

    ports = ['445','135','6379']
    proxy = '127.0.0.1:1080' ## socks5 代理
    relative_directory = pathlib.Path(__file__).parent.parent  # OneForAll代码相对路径
    data_storage_dir = relative_directory.joinpath('data')  # 数据存放目录


    GREEN       = "\033[32m"
    RED         = "\033[0;31m"
    BLUE        = "\033[94m"
    ORANGE      = "\033[33m"
    Timeout     = 500
    filename    = 'out\\%s.xlsx' % time.strftime("%Y-%m-%d-%H-%M", time.localtime(time.time()))

    FOFA_EMAIL = '820340571@qq.com'
    Apikey = '6f05e37f7024dfc1c2c6836c361ad0ca' # 使用时替换此处Apikey

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
    Supporting CIDR format!

    python3 fofa.py [options]

Options:
    -i  ip        eg : python3 fofa-Keyspider.py -i 8.8.8.8 8.8.8.0/24 8.8.8.8/16
    -f  ip_file   eg : python3 fofa-Keyspider.py -f 1.txt
    -k  keyword   eg : python3 fofa-Keyspider.py -k app="Solr"
'''

