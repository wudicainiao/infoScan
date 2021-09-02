from common.module import Module


class SiteDossier(Module):
    def __init__(self, domain, q_results, args, q_targets):
        Module.__init__(self)
        self.domain = domain
        self.module = 'Dataset'
        self.source = 'SiteDossierQuery'
        self.addr = 'http://www.sitedossier.com/parentdomain/'
        self.delay = 2
        self.page_num = 1
        self.per_page_num = 100
        self.q_results = q_results
        self.proxy = args.proxy
        self.q_targets = q_targets

    def query(self):
        """
        向接口查询子域并做子域匹配
        """
        while True:
            self.header = self.get_header()
            self.proxy = self.get_proxy(self.source)
            url = f'{self.addr}{self.domain}/{self.page_num}'
            resp = self.get(url)
            subdomains = self.match_subdomains(resp)
            if not subdomains:  # 没有发现子域名则停止查询
                break
            self.subdomains.update(subdomains)
            # 搜索页面没有出现下一页时停止搜索
            if 'Show next 100 items' not in resp.text:
                break
            self.page_num += self.per_page_num

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
    query = SiteDossier(domain, q_results, args, q_targets)
    query.run()


if __name__ == '__main__':
    run('example.com')
