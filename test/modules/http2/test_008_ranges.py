import os
import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestGet:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        destdir = os.path.join(env.gen_dir, 'apache/htdocs/test1')
        env.make_data_file(indir=destdir, fname="data-100m", fsize=100*1024*1024)
        conf = H2Conf(env=env, extras={
            'base': [
                'LogFormat "{\\"request\\": \\"%r\\", \\"status\\": \\"%>s\\", \\"recv\\": %I, \\"sent\\": %O, \\"ms\\": %D}" combined',
            ]
        })
        conf.add_vhost_cgi(
            proxy_self=True, h2proxy_self=True
        ).add_vhost_test1(
            proxy_self=True, h2proxy_self=True
        )
        conf.install()
        assert env.apache_restart() == 0

    def test_h2_008_01(self, env, repeat):
        path = '/002.jpg'
        url = env.mkurl("https", "test1", path)
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert "HTTP/2" == r.response["protocol"]
        h = r.response["header"]
        assert "accept-ranges" in h
        assert "bytes" == h["accept-ranges"]
        assert "content-length" in h
        clen = h["content-length"]
        assert int(clen) == 90364
        # get the first 1024 bytes of the resource, 206 status, but content-length as original
        for i in range(10):
            r = env.curl_get(url, 5, options=["-H", "range: bytes=0-1023"])
            if r.response["status"] != 503:
                break
        assert 206 == r.response["status"]
        assert "HTTP/2" == r.response["protocol"]
        assert 1024 == len(r.response["body"])
        assert "content-length" in h
        assert clen == h["content-length"]

    def test_h2_008_02(self, env, repeat):
        path = '/data-100m'
        url = env.mkurl("https", "test1", path)
        r = env.curl_get(url, 5, options=[
            '--limit-rate', '2k', '-m', '2'
        ])
        assert r.exit_code != 0, f'{r}'
