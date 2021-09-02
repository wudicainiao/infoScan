from common.module import Module


class IP138(Module):
    def __init__(self, domain, q_results, args, q_targets):
        Module.__init__(self)
        self.domain = domain
        self.module = 'Dataset'
        self.source = 'IP138Query'
        self.addr = 'https://site.ip138.com/{domain}/domain.htm'
        self.q_results = q_results
        self.proxy = args.proxy
        self.q_targets = q_targets

    def query(self):
        """
        向接口查询子域并做子域匹配
        """
        self.header = self.get_header()
        self.proxy = self.get_proxy(self.source)
        self.addr = self.addr.format(domain=self.domain)
        resp = self.get(self.addr)
        self.subdomains = self.collect_subdomains(resp)

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
    query = IP138(domain, q_results, args, q_targets)
    query.run()


if __name__ == '__main__':
    run('example.com')
