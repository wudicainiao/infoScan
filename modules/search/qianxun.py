from common.module import Module


class QianXun(Module):
    def __init__(self, domain, q_results, args, q_targets):
        Module.__init__(self)
        self.domain = domain
        self.module = 'Query'
        self.source = 'QianXunQuery'
        self.q_results = q_results
        self.proxy = args.proxy
        self.q_targets = q_targets

    def query(self):
        """
        向接口查询子域并做子域匹配
        """
        self.header = self.get_header()
        self.proxy = self.get_proxy(self.source)
        #data = r"ecmsfrom=121.226.26.122&show=%E5%8C%97%E4%BA%AC%E5%B8%82&num={}&classid=0&keywords={}".format(num, self.domain)
        num = 1
        while True:
            data = {'ecmsfrom': '111.206.66.112',
                    'show': r'%E5%8C%97%E4%BA%AC%E5%B8%82',
                    'num': '',
                    'classid': '0',
                    'keywords': self.domain}
            url = f'https://www.dnsscan.cn/dns.html'
            resp = self.post(url, data)
            subdomains = self.match_subdomains(resp)
            if not subdomains:  # 没有发现子域名则停止查询
                break
            self.subdomains.update(subdomains)
            if '<div id="page" class="pagelist">' not in resp.text:
                break
            if '<li class="disabled"><span>&raquo;</span></li>' in resp.text:
                break
            num += 1
        for i in list(self.subdomains):
            self.q_targets.put(i)

    def run(self):
        """
        类执行入口
        """
        self.query()
        self.finish()


def run(domain, q_results, args, q_targets):
    """
    类统一调用入口

    :param str domain: 域名
    """
    query = QianXun(domain, q_results, args, q_targets)
    query.run()


if __name__ == '__main__':
    run('example.com')
