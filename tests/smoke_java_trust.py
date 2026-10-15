#!/usr/bin/env python3
"""Run as root in a disposable sandbox image, passing Nix JDK java executables.

Exercises the real Ubuntu CA hook and HTTPS verification without external
network access. The temporary CA is removed even when a check fails.
"""

import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


class Response(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"trusted\n")

    def log_message(self, *args):
        pass


@contextlib.contextmanager
def endpoint(certificate, key):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Response)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://localhost:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def main(javas):
    if os.geteuid() != 0 or not javas:
        raise SystemExit("Run as root in a disposable image: smoke_java_trust.py JAVA [JAVA ...]")
    environment = os.environ.copy()
    for line in Path("/etc/environment").read_text().splitlines():
        name, value = line.split("=", 1)
        environment[name] = value
    assert environment["JAVAX_NET_SSL_TRUSTSTORE"] == "/etc/ssl/certs/java/cacerts"
    installed = Path("/usr/local/share/ca-certificates/sandbox-java-trust-test.crt")
    if installed.exists():
        raise SystemExit(f"Refusing to overwrite {installed}")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        source = directory / "TrustProbe.java"
        source.write_text('''
import javax.net.ssl.*;
import java.net.URI;
import java.security.KeyStore;
class TrustProbe {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            var factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore)null);
            for (var manager : factory.getTrustManagers())
                if (manager instanceof X509TrustManager x509)
                    System.out.println(x509.getAcceptedIssuers().length);
        } else {
            var connection = (HttpsURLConnection)URI.create(args[0]).toURL().openConnection();
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            System.out.write(connection.getInputStream().readAllBytes());
        }
    }
}
''')
        certificates = []
        for number in range(2):
            prefix = directory / str(number)
            ca, ca_key = str(prefix) + "-ca.crt", str(prefix) + "-ca.key"
            key, csr, certificate = str(prefix) + ".key", str(prefix) + ".csr", str(prefix) + ".crt"
            run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", f"/CN=Sandbox Java test {number}", "-keyout", ca_key, "-out", ca)
            run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                "-keyout", key, "-out", csr)
            extensions = directory / "extensions"
            extensions.write_text("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n")
            run("openssl", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
                "-CAcreateserial", "-days", "1", "-extfile", str(extensions), "-out", certificate)
            certificates.append((ca, certificate, key))

        def probe(java, *args):
            return subprocess.run([java, str(source), *args], env=environment,
                                  capture_output=True, text=True, timeout=30)

        def verify(trusted):
            for number, (_, certificate, key) in enumerate(certificates):
                with endpoint(certificate, key) as url:
                    for java in javas:
                        result = probe(java, url)
                        if number == trusted:
                            assert result.returncode == 0 and result.stdout == "trusted\n", f"{java}: {result.stderr}"
                        else:
                            assert result.returncode != 0 and "SSLHandshakeException" in result.stderr, result

        # Monitor does this on startup, including on an existing workspace.
        run("update-ca-certificates", "--fresh")
        baseline = {java: int(probe(java).stdout) for java in javas}
        assert all(count > 50 for count in baseline.values()), baseline
        verify(None)
        try:
            for trusted in range(2):
                installed.write_bytes(Path(certificates[trusted][0]).read_bytes())
                run("update-ca-certificates", "--fresh")
                verify(trusted)
                for java in javas:
                    count = int(probe(java).stdout)
                    assert count == baseline[java] + 1, (java, baseline[java], count)
        finally:
            installed.unlink(missing_ok=True)
            run("update-ca-certificates", "--fresh")
        verify(None)
        for java in javas:
            assert int(probe(java).stdout) == baseline[java]
            print(f"PASS {java}: public roots, CA addition, rotation, removal, HTTPS verification")


if __name__ == "__main__":
    main(sys.argv[1:])
