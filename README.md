# inference-proxy

A loopback HTTP proxy that injects an inference-service token, so a sandboxed AI coding agent
(e.g. Claude Code) can use an inference API **without ever holding the real token**.

```
sandboxed client                    inference-proxy (outside the sandbox)        inference service
  base URL = http://127.0.0.1:PORT  ->  checks the local key, swaps in the token  ->  https://upstream
  token    = random local key           forwards only to the one --upstream host
```

The real token is read once on stdin and kept in memory only, wiped on exit. The client gets a
random per-launch key that is useless anywhere but on this machine, against this proxy instance.
Run one instance per inference service, so each instance only holds one token and can only reach
one host.

## Behaviour

- Listens on `127.0.0.1` only, on a port the kernel picks, and prints `port=<n>` on stdout.
  The launcher reads the port from that pipe, so another local process cannot squat a known
  port and pose as the proxy.
- Accepts only `GET` / `POST` on paths under `/v1/` made of plain `[A-Za-z0-9_.-]` segments.
  Dot segments, empty segments, `%`-encodings, `;` parameters and absolute-form targets are
  refused, so nothing can be normalised upstream into another path.
- Checks the local key (`Authorization: Bearer ...` or `x-api-key: ...`) in constant time, before
  anything is sent upstream.
- Forwards only an allowlist of request headers (`accept*`, `content-type`, `user-agent`,
  `x-app`, `anthropic-*`, `x-stainless-*`, `x-claude-code-*`). Everything else is dropped,
  including the client's credentials and headers such as `X-Original-URL` that can make some
  servers route to another path.
- Adds the real token and forwards over TLS with certificate verification (system CA store) to
  the single `--upstream` origin. The client can never choose another host.
- Relays the response byte for byte (`Connection: close` on both sides), so streaming responses
  (server-sent events) work without the proxy parsing them.
- Logs one line per request (method, path, status) to stderr. Never logs headers or bodies.
- Marks itself non-dumpable at startup: a crash writes no core dump (which would contain the
  token), and other processes of the same user cannot read its memory.

## Usage

stdin: line 1 is the local key (at least 32 printable characters), line 2 is the real token.
Further lines are ignored, so `pass show` output can be piped as is.

```bash
key="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
coproc PROXY { exec inference-proxy --upstream https://api.example.ch [--auth x-api-key]; }
{ printf '%s\n' "$key"; pass show work/token; } >&"${PROXY[1]}"
exec {PROXY[1]}>&-
IFS= read -r port <&"${PROXY[0]}"

ANTHROPIC_BASE_URL="http://127.0.0.1:${port#port=}" ANTHROPIC_AUTH_TOKEN="$key" claude
```

- `--upstream`: `https://host[:port][/base-path]`. The base path is prepended to every request.
- `--port`: listen on a fixed port instead of a kernel-chosen one. Only for debugging: a fixed
  port can be taken first by another local process.
- `--auth`: how the upstream expects the token: `bearer` (default, `Authorization: Bearer`) or
  `x-api-key`.

## Build prerequisites: Rust toolchain

Make sure to install the latest stable Rust to have all the security patches, in the compiler,
the standard library and the crate versions it can build. A distribution Rust is often too old
for the latest crate releases.

Install Rust **root-owned under `/usr/local`**, so the compiler that builds the token-holding
binary is read-only for every other user, including the sandbox. The standalone installer is
GPG-signed by the Rust project, which is stronger than a hash downloaded from the same server.
The commands below always fetch the current stable version; rerun them to update.

```bash
VER=$(curl -sSf https://static.rust-lang.org/dist/channel-rust-stable.toml \
  | awk '/^\[pkg.rust\]/{f=1} f && /^version/ && !v {v=$3} END{print v}' | tr -d '"')
echo "$VER"
T=x86_64-unknown-linux-gnu
cd "$(mktemp -d)"
curl -sSfO "https://static.rust-lang.org/dist/rust-$VER-$T.tar.xz{,.asc,.sha256}"

export GNUPGHOME="$(mktemp -d)"
curl -sSf https://static.rust-lang.org/rust-key.gpg.ascii | gpg --import
gpg --fingerprint
gpg --verify "rust-$VER-$T.tar.xz.asc" "rust-$VER-$T.tar.xz"
sha256sum -c "rust-$VER-$T.tar.xz.sha256"
unset GNUPGHOME
```

Check before going further:

- the fingerprint matches the one published on
  <https://forge.rust-lang.org/infra/other-installation-methods.html>;
- `gpg --verify` reports `Good signature from "Rust Language (Tag and Release Signing Key)"`
  (a warning that the key is not certified is expected for a freshly imported key);
- `sha256sum -c` prints `OK`.

Then install and check:

```bash
tar xf "rust-$VER-$T.tar.xz"
sudo "./rust-$VER-$T/install.sh" --prefix=/usr/local
/usr/local/bin/rustc --version
```

`/usr/local/bin` comes before `/usr/bin` in `PATH`, so it takes precedence over a distribution
Rust. Uninstall with `sudo /usr/local/lib/rustlib/uninstall.sh`.

## Build, test, install

```bash
cargo build --release --locked
PROXY_BIN=target/release/inference-proxy python3 -m unittest discover -s tests
cargo test --locked
sudo install -o root -g root -m 755 target/release/inference-proxy /usr/local/bin/
```

`--locked` builds exactly the dependency versions in `Cargo.lock`, whose SHA256 checksums cargo
verifies on download. Review `Cargo.lock` changes like code.

Install the binary root-owned and outside any directory the sandbox can write to: the sandbox
must not be able to replace the program that receives the token.

## Dependencies

| Crate | Why |
|---|---|
| `rustls` (ring backend) | TLS to the upstream; memory-safe, no OpenSSL |
| `rustls-native-certs` | Trust the system CA store (honours `SSL_CERT_FILE`) |
| `httparse` | Strict HTTP/1.x request parsing, no dependencies |
| `zeroize` | Wipe the key and token from memory when dropped |
| `libc` | One `prctl(PR_SET_DUMPABLE, 0)` call at startup |

No async runtime and no HTTP framework: one thread per connection, with a cap on concurrent
connections.

## Limitations

- The client can still *use* the service through the proxy, from this machine, while it runs.
- Any local process that learns the local key can use the proxy too; the key changes per launch.
- Plain HTTP between client and proxy is only on the loopback interface.
- A request body is buffered in memory (up to 32 MiB, 32 connections at once), so a hostile
  client can make the proxy use about 1 GiB.
- Wiping memory is best effort: the token is copied into each outgoing request buffer, which is
  wiped after use, but the kernel and TLS library may hold transient copies.
