import inspect
import logging
import os
import shutil
import struct
import subprocess
import time
from datetime import timedelta, datetime

import pytest
import websockets.frames as ws_frames
from pyhttpd.result import ExecResult

from .env import H2Conf, H2TestEnv


log = logging.getLogger(__name__)


PING_FRAME = bytes.fromhex('89 85 00 00 00 00 01 02 03 04 05')
# code 1000, which seems to be defined as "ok" (not in the spec, but hey)
CLOSE_FRAME = bytes.fromhex('88 82 00 00 00 00 03 E8')

HEX_CLOSE_NORMAL = '88 02 03 e8'

class WsFrame:

    CONT = 0
    TEXT = 1
    BINARY = 2
    CLOSE = 8
    PING = 9
    PONG = 10

    OP_NAMES = [
        "CONT",
        "TEXT",
        "BINARY",
        "???",
        "???",
        "???",
        "???",
        "???",
        "CLOSE",
        "PING",
        "PONG",
    ]

    def __init__(self, opcode: int, fin: bool, mask: bytes, data: bytes):
        self.opcode = opcode
        self.fin = fin
        self.mask = mask
        self.data = data
        self.length = len(data)

    def __repr__(self):
        return f'WsFrame[{self.OP_NAMES[self.opcode]} fin={self.fin}, mask={self.mask}, len={len(self.data)}]'


class WsFrameReader:

    def __init__(self, data: bytearray):
        self.data = data

    def _read(self, n: int):
        if len(self.data) < n:
            raise EOFError(f'have {len(self.data)} bytes left, but {n} requested')
        elif n == 0:
            return b''
        chunk = self.data[:n]
        del self.data[:n]
        return chunk

    def next_frame(self):
        data = self._read(2)
        h1, h2 = struct.unpack("!BB", data)
        log.info(f'parsed h1={h1} h2={h2} from {data}')
        fin = True if h1 & 0xf0 else False
        opcode = h1 & 0xf
        has_mask = True if h2 & 0x80 else False
        mask = None
        dlen = h2 & 0x7f
        if dlen == 126:
            (dlen,) = struct.unpack("!H", self._read(2))
        elif dlen == 127:
            (dlen,) = struct.unpack("!Q", self._read(8))
        if has_mask:
            mask = self._read(4)
        return WsFrame(opcode=opcode, fin=fin, mask=mask, data=self._read(dlen))

    def eof(self):
        return len(self.data) == 0

    @classmethod
    def parse(cls, data: bytes):
        frames = []
        reader = WsFrameReader(data=data)
        while not reader.eof():
            frames.append(reader.next_frame())
        return frames


def ws_run(env: H2TestEnv, path, do_input=None, inbytes=None, send_close=True,
           timeout=5, scenario='ws-stdin', wait_close=0):
    h2ws = os.path.join(env.clients_dir, 'h2ws')
    if not os.path.exists(h2ws):
        pytest.fail(f'test client not build: {h2ws}')
    args = [
        h2ws, '-vv', '-c', f'localhost:{env.http_port}',
        f'ws://cgi.{env.http_tld}:{env.http_port}{path}',
        scenario
    ]
    proc = subprocess.Popen(args=args, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if do_input is not None:
        do_input(proc)
    elif inbytes is not None:
        proc.stdin.write(inbytes)
        proc.stdin.flush()

    if wait_close > 0:
        time.sleep(wait_close)
    try:
        inbytes = CLOSE_FRAME if send_close else None
        pout, perr = proc.communicate(input=inbytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        log.error(f'ws_run: timeout expired')
        proc.kill()
        pout, perr = proc.communicate(timeout=timeout)
    lines = pout.decode().splitlines()
    infos = [line for line in lines if line.startswith('[1] ')]
    if len(infos) > 0 and infos[0] == '[1] :status: 200':
        hex_content = ' '.join([line for line in lines if not line.startswith('[1] ')])
        frames = WsFrameReader.parse(bytearray.fromhex(hex_content))
    else:
        frames = []
    return ExecResult(args=args, exit_code=proc.returncode,
                      stdout=pout, stderr=perr), infos, frames


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestWebSockets:


    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
              f'  ProxyPass /ws/ http://127.0.0.1:{env.ws_port}/ upgrade=websocket \\',
              f'            timeout=10',
              f'  ProxyPassReverse /ws/ http://cgi.tests.httpd.apache.org:{env.http_port}/',
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
    def ws_server(self, env):
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
    def test_h2_800_01_ws_empty(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) == 1, f'{frames}'
        assert frames[0].opcode == WsFrame.CLOSE, f'{frames}'

    # a CONNECT using an invalid :protocol header
    def test_h2_800_02_fail_proto(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/', scenario='fail-proto')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 400', '[1] EOF'], f'{r}'

    # a valid CONNECT on a URL path that does not exist
    def test_h2_800_03_not_found(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/does-not-exist')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 404', '[1] EOF'], f'{r}'

    # a valid CONNECT on a URL path that is a normal HTTP resource
    # we do not want to see the original response body
    def test_h2_800_04_non_ws_resource(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/alive.json')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 502', '[1] EOF'], f'{r}'

    # a valid CONNECT on a URL path that sends delay response body
    # we error sending the original response body, leading to a RST
    def test_h2_800_05_non_ws_delay_resource(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/h2test/error?body_delay=100ms')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 502', '[1] EOF'], f'{r}'

    # a CONNECT missing the sec-webSocket-version header
    def test_h2_800_06_miss_version(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/', scenario='miss-version')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 400', '[1] EOF'], f'{r}'

    # a CONNECT missing the :path header
    def test_h2_800_07_miss_path(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/', scenario='miss-path')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] RST'], f'{r}'

    # a CONNECT missing the :scheme header
    def test_h2_800_08_miss_scheme(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/', scenario='miss-scheme')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] RST'], f'{r}'

    # a CONNECT missing the :authority header
    def test_h2_800_09_miss_authority(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/', scenario='miss-authority')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] RST'], f'{r}'

    # a correct websocket CONNECT with ping pong exchange
    def test_h2_800_10_ws_ping(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/echo/', inbytes=PING_FRAME)
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) == 2, f'{frames}'
        assert frames[0].opcode == WsFrame.PONG, f'{frames}'
        assert frames[1].opcode == WsFrame.CLOSE, f'{frames}'

    def test_h2_800_11_ws_timed_pings(self, env: H2TestEnv, ws_server):
        frame_count = 5
        def do_send(proc):
            for _ in range(frame_count):
                try:
                    proc.stdin.write(PING_FRAME)
                    proc.stdin.flush()
                    proc.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    pass

        r, infos, frames = ws_run(env, path='/ws/echo/', do_input=do_send)
        assert r.exit_code == 0
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) == frame_count + 1, f'{frames}'
        assert frames[-1].opcode == WsFrame.CLOSE, f'{frames}'
        for i in range(frame_count):
            assert frames[i].opcode == WsFrame.PONG, f'{frames}'

    # CONNECT to path that closes immediately
    def test_h2_800_12_ws_unknown(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/unknown')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) == 1, f'{frames}'
        # expect a CLOSE with code=4999, reason='path unknown'
        assert frames[0].opcode == WsFrame.CLOSE, f'{frames}'
        assert frames[0].data == bytes.fromhex('13 87 70 61 74 68 20 75 6e 6b 6e 6f 77 6e'), f'{frames}'

    # CONNECT with text answer
    def test_h2_800_13_ws_text(self, env: H2TestEnv, ws_server):
        r, infos, frames = ws_run(env, path='/ws/text/')
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) == 2, f'{frames}'
        assert frames[0].opcode == WsFrame.TEXT, f'{frames}'
        assert frames[1].opcode == WsFrame.CLOSE, f'{frames}'

    # CONNECT with streaming a file
    @pytest.mark.parametrize("fname,flen", [
        ("data-1k", 1000),
        ("data-10k", 10000),
        ("data-100k", 100*1000),
        ("data-1m", 1000*1000),
    ])
    def test_h2_800_14_ws_file(self, env: H2TestEnv, ws_server, fname, flen):
        r, infos, frames = ws_run(env, path=f'/ws/file/{fname}', wait_close=0.5)
        assert r.exit_code == 0, f'{r}'
        assert infos == ['[1] :status: 200', '[1] EOF'], f'{r}'
        assert len(frames) > 0
        total_len = sum([f.length for f in frames if f.opcode == WsFrame.BINARY])
        assert total_len == flen, f'{frames}'

