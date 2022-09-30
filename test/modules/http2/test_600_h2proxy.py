import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestH2Proxy:

    def test_h2_600_01(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "SetEnvIf Host (.+) X_HOST=$1",
            ]
        })
        conf.add_vhost_cgi(h2proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2proxy/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["json"]["protocol"] == "HTTP/2.0"
        assert r.response["json"]["https"] == "on"
        assert r.response["json"]["ssl_protocol"] != ""
        assert r.response["json"]["h2"] == "on"
        assert r.response["json"]["h2push"] == "off"
        assert r.response["json"]["host"] == f"cgi.{env.http_tld}:{env.https_port}"

    def test_h2_600_02(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "SetEnvIf Host (.+) X_HOST=$1",
                f"ProxyPreserveHost on",
                f"ProxyPass /h2c/ h2c://127.0.0.1:{env.http_port}/",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2c/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["json"]["protocol"] == "HTTP/2.0"
        assert r.response["json"]["https"] == ""
        # the proxied backend sees Host header as passed on front
        assert r.response["json"]["host"] == f"cgi.{env.http_tld}:{env.https_port}"
        assert r.response["json"]["h2_original_host"] == ""

    def test_h2_600_03(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "SetEnvIf Host (.+) X_HOST=$1",
                f"ProxyPreserveHost off",
                f"ProxyPass /h2c/ h2c://127.0.0.1:{env.http_port}/",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2c/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["json"]["protocol"] == "HTTP/2.0"
        assert r.response["json"]["https"] == ""
        # the proxied backend sees Host as using in connecting to it
        assert r.response["json"]["host"] == f"127.0.0.1:{env.http_port}"
        assert r.response["json"]["h2_original_host"] == ""

    # lets do some error tests
    def test_h2_600_30(self, env):
        conf = H2Conf(env)
        conf.add_vhost_cgi(h2proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/error?status=500")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 500
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/error?error=timeout")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 408

    # produce an error during response body
    def test_h2_600_31(self, env, repeat):
        conf = H2Conf(env)
        conf.add_vhost_cgi(h2proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/error?body_error=timeout")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 503
