import inspect
import os
import shutil
import subprocess
import time
from datetime import timedelta, datetime

import pytest

from .env import H2Conf, H2TestEnv
from pyhttpd.curl import CurlPiper


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestWebSockets:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
              f'  ProxyPass /ws/echo/ http://127.0.0.1:{env.ws_port}/ upgrade=websocket \\',
              f'            timeout=1',
              f'  ProxyPassReverse /ws/echo/ http://cgi.tests.httpd.apache.org:{env.http_port}/',
              f'LogLevel proxy:trace8',
            ]
        })
        conf.add_vhost_cgi(proxy_self=True, h2proxy_self=True).install()
        assert env.apache_restart() == 0

    def check_alive(self, env, timeout=5):
        url = f'http://localhost:{env.ws_port}/'
        end = datetime.now() + timedelta(seconds=timeout)
        while datetime.now() < end:
            r = env.curl_get(url, 5)
            if r.exit_code == 0:
                return True
            time.sleep(.1)
        return False

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def _rmrf(self, path):
        if os.path.exists(path):
            return shutil.rmtree(path)

    @pytest.fixture(autouse=True, scope='class')
    def ws_echo(self, env):
        run_dir = os.path.join(env.gen_dir, 'ws-echo-server')
        err_file = os.path.join(run_dir, 'stderr')
        self._rmrf(run_dir)
        self._mkpath(run_dir)

        with open(err_file, 'w') as cerr:

            cmd = os.path.join(os.path.dirname(inspect.getfile(TestWebSockets)),
                               'ws_server.py')
            args = [cmd, '--port', str(env.ws_port)]
            p = subprocess.Popen(args=args, cwd=run_dir, stderr=cerr,
                                 stdout=cerr)
            assert self.check_alive(env)
            yield
            p.terminate()

    # a correct websocket CONNECT, not sending/receiving anything
    def test_h2_800_01_ws_empty(self, env: H2TestEnv, ws_echo):
        h2ws = os.path.join(env.clients_dir, 'h2ws')
        if not os.path.exists(h2ws):
            pytest.fail(f'test client not build: {h2ws}')
        r = env.run(args=[
            h2ws, '-v', '-c', f'localhost:{env.http_port}',
            f'ws://cgi.{env.http_tld}:{env.http_port}/ws/echo/',
            'ws-empty'
        ])
        assert r.exit_code == 0, f'{r}'
        assert "[1] :status: 200\n" == r.stdout, f'{r}'

    # a CONNECT using an invalid :protocol header
    def test_h2_800_02_fail_proto(self, env: H2TestEnv, ws_echo):
        h2ws = os.path.join(env.clients_dir, 'h2ws')
        if not os.path.exists(h2ws):
            pytest.fail(f'test client not build: {h2ws}')
        r = env.run(args=[
            h2ws, '-v', '-c', f'localhost:{env.http_port}',
            f'ws://cgi.{env.http_tld}:{env.http_port}/ws/echo/',
            'fail-proto'
        ])
        assert r.exit_code == 0, f'{r}'
        assert r.stdout.startswith("[1] :status: 400\n"), f'{r}'

    # a valid CONNECT on a URL path that does not exist
    def test_h2_800_03_not_found(self, env: H2TestEnv, ws_echo):
        h2ws = os.path.join(env.clients_dir, 'h2ws')
        if not os.path.exists(h2ws):
            pytest.fail(f'test client not build: {h2ws}')
        r = env.run(args=[
            h2ws, '-v', '-c', f'localhost:{env.http_port}',
            f'ws://cgi.{env.http_tld}:{env.http_port}/does-not-exist',
            'ws-empty'
        ])
        assert r.exit_code == 0, f'{r}'
        assert r.stdout.startswith("[1] :status: 404\n"), f'{r}'

    # a valid CONNECT on a URL path that is a normal HTTP resource
    # we do not want to see the original response body
    def test_h2_800_04_non_ws_resource(self, env: H2TestEnv, ws_echo):
        h2ws = os.path.join(env.clients_dir, 'h2ws')
        if not os.path.exists(h2ws):
            pytest.fail(f'test client not build: {h2ws}')
        r = env.run(args=[
            h2ws, '-v', '-c', f'localhost:{env.http_port}',
            f'ws://cgi.{env.http_tld}:{env.http_port}/alive.json',
            'ws-empty'
        ])
        assert r.exit_code == 0, f'{r}'
        assert r.stdout == "[1] :status: 502\n", f'{r}'

    # a valid CONNECT on a URL path that sends delay response body
    # we error sending the original response body, leading to a RST
    def test_h2_800_05_non_ws_delay_resource(self, env: H2TestEnv, ws_echo):
        h2ws = os.path.join(env.clients_dir, 'h2ws')
        if not os.path.exists(h2ws):
            pytest.fail(f'test client not build: {h2ws}')
        r = env.run(args=[
            h2ws, '-v', '-c', f'localhost:{env.http_port}',
            f'ws://cgi.{env.http_tld}:{env.http_port}/h2test/error?body_delay=100ms',
            'ws-empty'
        ])
        assert r.exit_code == 0, f'{r}'
        assert r.stdout == "[1] :status: 502\n", f'{r}'

    # a CONNECT missing the sec-webSocket-version header
    def test_h2_800_06_miss_version(self, env: H2TestEnv, ws_echo):
        h2ws = os.path.join(env.clients_dir, 'h2ws')
        if not os.path.exists(h2ws):
            pytest.fail(f'test client not build: {h2ws}')
        r = env.run(args=[
            h2ws, '-v', '-c', f'localhost:{env.http_port}',
            f'ws://cgi.{env.http_tld}:{env.http_port}/ws/echo/',
            'miss-version'
        ])
        assert r.exit_code == 0, f'{r}'
        assert r.stdout.startswith("[1] :status: 400\n"), f'{r}'

    # a CONNECT missing the :path header
    def test_h2_800_07_miss_path(self, env: H2TestEnv, ws_echo):
        h2ws = os.path.join(env.clients_dir, 'h2ws')
        if not os.path.exists(h2ws):
            pytest.fail(f'test client not build: {h2ws}')
        r = env.run(args=[
            h2ws, '-v', '-c', f'localhost:{env.http_port}',
            f'ws://cgi.{env.http_tld}:{env.http_port}/ws/echo/',
            'miss-path'
        ])
        assert r.exit_code == 0, f'{r}'
        assert r.stdout == "[1] RST\n", f'{r}'

    # a CONNECT missing the :scheme header
    def test_h2_800_08_miss_scheme(self, env: H2TestEnv, ws_echo):
        h2ws = os.path.join(env.clients_dir, 'h2ws')
        if not os.path.exists(h2ws):
            pytest.fail(f'test client not build: {h2ws}')
        r = env.run(args=[
            h2ws, '-v', '-c', f'localhost:{env.http_port}',
            f'ws://cgi.{env.http_tld}:{env.http_port}/ws/echo/',
            'miss-path'
        ])
        assert r.exit_code == 0, f'{r}'
        assert r.stdout == "[1] RST\n", f'{r}'

    # a CONNECT missing the :authority header
    def test_h2_800_09_miss_authority(self, env: H2TestEnv, ws_echo):
        h2ws = os.path.join(env.clients_dir, 'h2ws')
        if not os.path.exists(h2ws):
            pytest.fail(f'test client not build: {h2ws}')
        r = env.run(args=[
            h2ws, '-v', '-c', f'localhost:{env.http_port}',
            f'ws://cgi.{env.http_tld}:{env.http_port}/ws/echo/',
            'miss-authority'
        ])
        assert r.exit_code == 0, f'{r}'
        assert r.stdout == "[1] RST\n", f'{r}'

    # a correct websocket CONNECT, send from stdin
    def test_h2_800_10_ws_stdin(self, env: H2TestEnv, ws_echo):
        pytest.skip('WIP')
        h2ws = os.path.join(env.clients_dir, 'h2ws')
        if not os.path.exists(h2ws):
            pytest.fail(f'test client not build: {h2ws}')
        # a PING frame with 5 bytes of data
        inbytes = bytes.fromhex('89 85 00 00 00 00 01 02 03 04 05')
        r = env.run(args=[
            h2ws, '-vv', '-c', f'localhost:{env.http_port}',
            f'ws://cgi.{env.http_tld}:{env.http_port}/ws/echo/',
            'ws-stdin'
        ], inbytes=inbytes)
        assert r.exit_code == 0, f'{r}'
        assert "[1] :status: 200\n" == r.stdout, f'{r}'

