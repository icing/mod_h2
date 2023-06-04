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

    def test_h2_800_01(self, env):
        url = env.mkurl("https", "cgi", "")
        r = env.nghttp().get(url, options=[
            '-Hprotocol: websocket', '-H:method: CONNECT'
        ])
        assert r.exit_code == 0, r
        assert r.response['status'] == 400

