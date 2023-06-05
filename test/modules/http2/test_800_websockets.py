import os
from datetime import timedelta

import pytest

from .env import H2Conf, H2TestEnv
from pyhttpd.curl import CurlPiper


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestWebSockets:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env)
        conf.add_vhost_cgi(proxy_self=True, h2proxy_self=True).install()
        assert env.apache_restart() == 0

    def test_h2_800_01(self, env: H2TestEnv):
        h2ws = os.path.join(env.clients_dir, 'h2ws')
        if not os.path.exists(h2ws):
            pytest.fail(f'test client not build: {h2ws}')

        r = env.run(args=[
            h2ws, '-v', '-c', f'localhost:{env.http_port}',
            f'ws://cgi.{env.http_tld}:{env.http_port}/h2test/echo'
        ])
        assert r.exit_code == 0, f'{r}'
        assert False, f'{r}'
        assert r.response['status'] == 400, f'{r}'

