"""End-to-end tests for the inference-proxy binary against a local TLS upstream.

Run: PROXY_BIN=target/release/inference-proxy python3 -m unittest discover -s tests
"""

import http.client
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROXY = os.environ.get("PROXY_BIN") or os.path.join(
    os.path.dirname(__file__), "..", "target", "release", "inference-proxy")
KEY = "k" * 40
TOKEN = "real-upstream-token-123"
SSE_CHUNKS = [b"event: a\ndata: 1\n\n", b"event: b\ndata: 2\n\n", b"event: c\ndata: 3\n\n"]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        Upstream.seen.append((self.path, dict(self.headers), body))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for chunk in SSE_CHUNKS:
            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")

    def log_message(self, *args):
        pass


class ProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        path = lambda name: os.path.join(cls.tmp.name, name)
        cls.cert = path("ca.pem")
        ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]
        run = lambda *args: subprocess.run(["openssl", *args], check=True, capture_output=True)
        run("req", "-x509", *ec, "-keyout", path("ca.key"), "-out", cls.cert, "-days", "1",
            "-subj", "/CN=test-ca")
        run("req", *ec, "-keyout", path("server.key"), "-out", path("server.csr"),
            "-subj", "/CN=localhost")
        with open(path("server.ext"), "w") as fh:
            fh.write("basicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost\n")
        run("x509", "-req", "-in", path("server.csr"), "-CA", cls.cert, "-CAkey", path("ca.key"),
            "-CAcreateserial", "-out", path("server.pem"), "-days", "1",
            "-extfile", path("server.ext"))
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(path("server.pem"), path("server.key"))
        cls.upstream.socket = ctx.wrap_socket(cls.upstream.socket, server_side=True)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        cls.up_port = cls.upstream.server_address[1]
        cls.bearer = cls.start_proxy("bearer")
        cls.apikey = cls.start_proxy("x-api-key")

    @classmethod
    def start_proxy(cls, auth, stdin=f"{KEY}\n{TOKEN}\n"):
        port = free_port()
        proc = subprocess.Popen(
            [PROXY, "--upstream", f"https://localhost:{cls.up_port}/gw",
             "--port", str(port), "--auth", auth],
            stdin=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "SSL_CERT_FILE": cls.cert})
        proc.stdin.write(stdin.encode())
        proc.stdin.close()
        line = proc.stderr.readline().decode()
        if "listening" not in line:
            proc.wait(5)
            proc.stderr.close()
            return proc, None, line
        return proc, port, line

    @classmethod
    def tearDownClass(cls):
        for proc, _, _ in (cls.bearer, cls.apikey):
            proc.terminate()
            proc.wait(5)
            proc.stderr.close()
        cls.upstream.shutdown()
        cls.upstream.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        Upstream.seen.clear()

    def request(self, port, path="/v1/messages?beta=true", headers=None, body=b'{"x":1}'):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", path, body=body, headers=headers or {})
        resp = conn.getresponse()
        chunks = []
        while chunk := resp.read1(65536):
            chunks.append(chunk)
        conn.close()
        return resp, chunks

    def test_missing_key_rejected_before_upstream(self):
        resp, _ = self.request(self.bearer[1])
        self.assertEqual(resp.status, 401)
        self.assertEqual(Upstream.seen, [])

    def test_wrong_key_rejected(self):
        resp, _ = self.request(self.bearer[1], headers={"Authorization": "Bearer " + "x" * 40})
        self.assertEqual(resp.status, 401)
        self.assertEqual(Upstream.seen, [])

    def test_bearer_token_replaced_and_stream_relayed(self):
        resp, chunks = self.request(
            self.bearer[1], headers={"Authorization": f"Bearer {KEY}", "anthropic-version": "1"})
        self.assertEqual(resp.status, 200)
        self.assertEqual(b"".join(chunks), b"".join(SSE_CHUNKS))
        path, headers, body = Upstream.seen[0]
        self.assertEqual(path, "/gw/v1/messages?beta=true")
        self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")
        self.assertNotIn("x-api-key", {k.lower() for k in headers})
        self.assertEqual(headers["anthropic-version"], "1")
        self.assertEqual(body, b'{"x":1}')
        self.assertNotIn(KEY, str(headers))

    def test_x_api_key_mode(self):
        resp, _ = self.request(self.apikey[1], headers={"x-api-key": KEY})
        self.assertEqual(resp.status, 200)
        _, headers, _ = Upstream.seen[0]
        self.assertEqual(headers["x-api-key"], TOKEN)
        self.assertNotIn("authorization", {k.lower() for k in headers})

    def test_paths_outside_v1_rejected(self):
        auth = {"Authorization": f"Bearer {KEY}"}
        for path in ("/admin", "/v1/../admin", "/v1/%2e%2e/admin", "http://evil.example/v1/x"):
            with self.subTest(path=path):
                resp, _ = self.request(self.bearer[1], path=path, headers=auth)
                self.assertEqual(resp.status, 403)
        self.assertEqual(Upstream.seen, [])

    def test_missing_token_exits(self):
        proc, port, line = self.start_proxy("bearer", stdin=f"{KEY}\n")
        self.assertIsNone(port)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("token missing", line)

    def test_non_https_upstream_refused(self):
        proc = subprocess.run(
            [PROXY, "--upstream", "http://localhost:1", "--port", "1"],
            input=f"{KEY}\n{TOKEN}\n".encode(), capture_output=True)
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
