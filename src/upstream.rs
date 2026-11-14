//  Copyright (c) 2026 ETH Zurich
//
//  SPDX-License-Identifier: BSL-1.0
//  Distributed under the Boost Software License, Version 1.0. (See accompanying
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

pub struct Connector {
    config: Arc<ClientConfig>,
}

impl Connector {
    /// TLS client trusting the system CA store; rustls-native-certs honours SSL_CERT_FILE.
    pub fn new() -> Result<Self, String> {
        let mut roots = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        if roots.is_empty() {
            return Err("no trusted CA certificates found".into());
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self { config: Arc::new(config) })
    }

    pub fn connect(&self, host: &str, port: u16) -> io::Result<TlsStream> {
        let name = ServerName::try_from(host.to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid host name"))?;
        let tcp = connect_tcp(host, port)?;
        tcp.set_read_timeout(Some(IDLE_TIMEOUT))?;
        tcp.set_write_timeout(Some(IDLE_TIMEOUT))?;
        let conn = ClientConnection::new(self.config.clone(), name).map_err(io::Error::other)?;
        Ok(StreamOwned::new(conn, tcp))
    }
}

fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "host did not resolve");
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = e,
        }
    }
    Err(last)
}
