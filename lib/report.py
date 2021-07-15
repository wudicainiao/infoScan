# -*- encoding: utf-8 -*-
# report template

import time
import sys
import codecs
import os
from lib.config import define


def report(_q_results):
    try:
        while not define.stop_me or _q_results.qsize() > 0:
            if _q_results.qsize() == 0:
                time.sleep(0.1)
                continue

            while _q_results.qsize() > 0:
                item = _q_results.get()
                if type(item) is str:
                    message = '[%s] %s' % (time.strftime('%H:%M:%S', time.localtime()), item)
                    print(message)
                    continue

    except Exception as e:
        print('[report error] %s %s' % (type(e), str(e)))
        import traceback
        traceback.print_exc()
        sys.exit(-1)
