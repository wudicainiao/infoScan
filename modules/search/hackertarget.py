from common.module import Module


class HackerTarget(Module):
    def __init__(self, domain, q_results, args, q_targets):
        Module.__init__(self)
        self.domain = domain
        self.module = 'Search'
        self.source = "HackerTargetQuery"
        self.addr = 'https://api.hackertarget.com/hostsearch/'
        self.q_results = q_results
        self.proxy = args.proxy
        self.q_targets = q_targets

    def query(self):
        """
        向接口查询子域并做子域匹配
        """
        self.header = self.get_header()
        self.proxy = self.get_proxy(self.source)
        params = {'q': self.domain}
        resp = self.get(self.addr, params)
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
    query = HackerTarget(domain, q_results, args, q_targets)
    query.run()


if __name__ == '__main__':
    run('example.com')
