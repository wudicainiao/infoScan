from common.module import Module


class DNSDumpster(Module):
    def __init__(self, domain, q_results, args, q_targets):
        Module.__init__(self)
        self.domain = domain
        self.module = 'Dataset'
        self.source = "DNSDumpsterQuery"
        self.addr = 'https://dnsdumpster.com/'
        self.q_results = q_results
        self.proxy = args.proxy
        self.q_targets = q_targets

    def query(self):
        """
        向接口查询子域并做子域匹配
        """
        self.header = self.get_header()
        self.header.update({'Referer': 'https://dnsdumpster.com'})
        self.proxy = self.get_proxy(self.source)
        resp = self.get(self.addr)
        if not resp:
            return
        self.cookie = resp.cookies
        data = {'csrfmiddlewaretoken': self.cookie.get('csrftoken'),
                'targetip': self.domain,
                'user':'free'}
        resp = self.post(self.addr, data)
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
    query = DNSDumpster(domain, q_results, args, q_targets)
    query.run()


if __name__ == '__main__':
    run('mi.com')
