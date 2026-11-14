<!--
    Copyright (c) 2026 ETH Zurich

    SPDX-License-Identifier: BSL-1.0
    Distributed under the Boost Software License, Version 1.0. (See accompanying
    file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
-->

# Installing the Rust toolchain

Use the latest stable Rust, to have all the security patches. Install it root-owned under
`/usr/local`, so the sandbox cannot modify the compiler that builds the token-holding binary.
The standalone installer is GPG-signed by the Rust project:

```bash
VER=$(curl -sSf https://static.rust-lang.org/dist/channel-rust-stable.toml \
  | awk '/^\[pkg.rust\]/{f=1} f && /^version/ && !v {v=$3} END{print v}' | tr -d '"')
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

Continue only if the fingerprint matches the one on
<https://forge.rust-lang.org/infra/other-installation-methods.html>, `gpg --verify` reports a
good signature and `sha256sum -c` prints `OK`:

```bash
tar xf "rust-$VER-$T.tar.xz"
sudo "./rust-$VER-$T/install.sh" --prefix=/usr/local
```

`/usr/local/bin` comes before `/usr/bin` in `PATH`, so this toolchain takes precedence over a
distribution Rust. Rerun the commands to update. Uninstall with
`sudo /usr/local/lib/rustlib/uninstall.sh`.
