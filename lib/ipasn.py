import sys
import queue
import zipfile
import sqlite3
from ipaddress import IPv4Address
from lib.config import define


class IPAsnInfo:
    def __init__(self):
        self.path = self.get_db_path()

    def get_db_path(self):
        zip_path = define.data_storage_dir.joinpath('ip2location.zip')
        db_path = define.data_storage_dir.joinpath('ip2location.db')
        if db_path.exists():
            return db_path
        zf = zipfile.ZipFile(str(zip_path))
        zf.extract('ip2location.db', define.data_storage_dir)
        return db_path

    def ip_to_int(self, ip):
        if isinstance(ip, int):
            return ip
        try:
            ipv4 = IPv4Address(ip)
        except Exception as e:
            logger.log('ERROR', e.args)
            return 0
        return int(ipv4)

    def run(self, q_targets, q_targets_ex):
        conn = sqlite3.connect(self.path)
        c = conn.cursor()

        while True:
            try:
                target = q_targets.get(timeout=0.2)
                ip = self.ip_to_int(target['ip'])
                cursor = c.execute(f"SELECT * FROM asn WHERE ip_from <= {ip} AND ip_to >= {ip} LIMIT 1;")
                for s in cursor:
                    ipc = target['ip'].split('.')
                    target['cidr'] = ipc[0] + '.' + ipc[1] + '.' + ipc[2] + '.0/24'
                    target['asn'] = s[3]
                    target['org'] = s[4]
                q_targets_ex.put(target)
            except queue.Empty:
                break
        conn.close()


if __name__ == "__main__":
    asn_info = IPAsnInfo()
    print(asn_info.find("188.81.94.77"))
