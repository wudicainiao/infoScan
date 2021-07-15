from gevent import socket
from lib.config import define




def creat_xlsx():
    if os.path.exists(define.filename) == False:
        s = 0
        wb = ws.Workbook()
        ws1 = wb.active
        if os.path.exists('out\\') == False:
            os.mkdir('out')
        word=['ip','host','title','port','protocol']
        for i in word:
            s = s + 1
            ws1.cell(row =1,column = s,value = i)
        wb.save(define.filename)
        #wb.close()
        print(define.RED+"[*]创建文件成功 %s"%define.filename)
    else:
        print(define.RED+"[*]文件已存在 文件为:%s 请稍后运行程序"%define.filename)

def is_port_open(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        if s.connect_ex((host, int(port))) == 0:
            return True
        else:
            return False
    except Exception as e:
        return False
    finally:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            s.close()
        except Exception as e:
            pass

def scan_given_ports(host, ports_open, port='80'):
    if port in define.ports:
        for p in define.ports:
            if is_port_open(host, p):
                ports_open.add(p)
    else:
        if is_port_open(host, port):
            ports_open.add(port)
        for p in define.ports:
            if is_port_open(host, p):
                ports_open.add(p)
