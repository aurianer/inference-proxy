//  Copyright (c) 2026 ETH Zurich
//
//  SPDX-License-Identifier: BSL-1.0
//  Distributed under the Boost Software License, Version 1.0. (See accompanying
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::config::{is_clean_path, Auth, Secrets, Upstream};
use crate::upstream::Connector;

const MAX_HEAD: usize = 64 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_BODY: usize = 32 * 1024 * 1024;
const BUFSIZE: usize = 64 * 1024;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);
const ALLOWED_PREFIX: &str = "/v1/";

// Allowlist, not denylist: headers such as X-Original-URL or X-HTTP-Method-Override can make
// some upstream stacks serve another path or method than the one validated here.
const FORWARDED_HEADERS: [&str; 6] =
    ["accept", "accept-encoding", "accept-language", "content-type", "user-agent", "x-app"];
const FORWARDED_PREFIXES: [&str; 3] = ["anthropic-", "x-stainless-", "x-claude-code-"];

pub struct Reject {
    status: u16,
    message: &'static str,
}

const fn reject(status: u16, message: &'static str) -> Reject {
    Reject { status, message }
}

struct Forward {
    head: Zeroizing<Vec<u8>>,
    body_len: usize,
    label: String,
}

pub struct Proxy {
    key: Zeroizing<String>,
    auth_line: Zeroizing<String>,
    upstream: Upstream,
    connector: Connector,
}

impl Proxy {
    pub fn new(secrets: Secrets, auth: Auth, upstream: Upstream, connector: Connector) -> Self {
        let name = match auth {
            Auth::Bearer => "Authorization: Bearer ",
            Auth::XApiKey => "x-api-key: ",
        };
        let mut auth_line = Zeroizing::new(String::with_capacity(name.len() + secrets.token.len() + 2));
        auth_line.push_str(name);
        auth_line.push_str(&secrets.token);
        auth_line.push_str("\r\n");
        Self { key: secrets.key, auth_line, upstream, connector }
    }

    pub fn handle(&self, mut client: TcpStream) {
        let _ = client.set_read_timeout(Some(CLIENT_TIMEOUT));
        let _ = client.set_write_timeout(Some(CLIENT_TIMEOUT));
        match self.serve(&mut client) {
            Ok(line) => log(&line),
            Err(r) => {
                log(&format!("rejected {} {}", r.status, r.message));
                let _ = reply(&mut client, r.status, r.message);
            }
        }
    }

    fn serve(&self, client: &mut TcpStream) -> Result<String, Reject> {
        let (mut buf, head_len) = read_head(client)?;
        let forward = self.build_request(&buf[..head_len])?;

        let mut body = Zeroizing::new(buf.split_off(head_len));
        if body.len() > forward.body_len {
            return Err(reject(400, "more data than Content-Length"));
        }
        let received = body.len();
        body.resize(forward.body_len, 0);
        client
            .read_exact(&mut body[received..])
            .map_err(|_| reject(400, "incomplete body"))?;

        let mut upstream = self
            .connector
            .connect(&self.upstream.host, self.upstream.port)
            .map_err(upstream_error)?;
        upstream
            .write_all(&forward.head)
            .and_then(|_| upstream.write_all(&body))
            .and_then(|_| upstream.flush())
            .map_err(upstream_error)?;

        let (status, bytes) = relay(&mut upstream, client);
        Ok(format!("{} -> {status} ({bytes} bytes)", forward.label))
    }

    /// Validates the client request and builds the upstream request head. Every check runs
    /// before anything is sent upstream.
    fn build_request(&self, head: &[u8]) -> Result<Forward, Reject> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        // The parser must agree on where the head ends, or bytes could hide between the two.
        match req.parse(head) {
            Ok(httparse::Status::Complete(n)) if n == head.len() => {}
            _ => return Err(reject(400, "malformed request")),
        }
        let method = req.method.unwrap_or("");
        let target = req.path.unwrap_or("");
        if method != "GET" && method != "POST" {
            return Err(reject(405, "method not allowed"));
        }
        if !is_path_allowed(target) {
            // httparse only accepts visible ASCII in the target, so it cannot forge log lines.
            let path: String = target.split('?').next().unwrap_or("").chars().take(200).collect();
            log(&format!("path not allowed: {method} {path}"));
            return Err(reject(403, "path not allowed"));
        }
        if !ct_eq(presented_key(req.headers), self.key.as_bytes()) {
            return Err(reject(401, "invalid local key"));
        }
        if has_header(req.headers, "transfer-encoding") {
            return Err(reject(411, "chunked request bodies are not supported"));
        }
        if has_header(req.headers, "expect") {
            return Err(reject(417, "Expect is not supported"));
        }
        let body_len = content_length(req.headers)?;

        let mut plain = format!(
            "{method} {}{target} HTTP/1.1\r\nHost: {}\r\n",
            self.upstream.base_path,
            self.upstream.host_header()
        )
        .into_bytes();
        for h in req.headers.iter().filter(|h| is_forwarded(h.name)) {
            plain.extend_from_slice(h.name.as_bytes());
            plain.extend_from_slice(b": ");
            plain.extend_from_slice(h.value);
            plain.extend_from_slice(b"\r\n");
        }
        let tail = format!("Content-Length: {body_len}\r\nConnection: close\r\n\r\n");

        // Exact capacity: the buffer holding the token never reallocates, so no copy of it is
        // left behind unwiped.
        let mut out = Zeroizing::new(Vec::with_capacity(plain.len() + self.auth_line.len() + tail.len()));
        out.extend_from_slice(&plain);
        out.extend_from_slice(self.auth_line.as_bytes());
        out.extend_from_slice(tail.as_bytes());

        let label = format!("{method} {}", target.split('?').next().unwrap_or(""));
        Ok(Forward { head: out, body_len, label })
    }
}

fn upstream_error(e: io::Error) -> Reject {
    log(&format!("upstream error: {e}"));
    reject(502, "upstream unreachable")
}

/// Origin-form target whose path is clean (see is_clean_path) and under /v1/.
pub fn is_path_allowed(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or("");
    path.starts_with(ALLOWED_PREFIX) && is_clean_path(path)
}

fn is_forwarded(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    FORWARDED_HEADERS.contains(&name.as_str())
        || FORWARDED_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Constant-time comparison for equal lengths; the key length is not secret.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn presented_key<'a>(headers: &[httparse::Header<'a>]) -> &'a [u8] {
    if let Some(h) = headers.iter().find(|h| h.name.eq_ignore_ascii_case("x-api-key")) {
        return h.value;
    }
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("authorization"))
        .and_then(|h| h.value.strip_prefix(b"Bearer "))
        .unwrap_or(b"")
}

fn has_header(headers: &[httparse::Header], name: &str) -> bool {
    headers.iter().any(|h| h.name.eq_ignore_ascii_case(name))
}

fn content_length(headers: &[httparse::Header]) -> Result<usize, Reject> {
    let mut length = None;
    for h in headers.iter().filter(|h| h.name.eq_ignore_ascii_case("content-length")) {
        let parsed = std::str::from_utf8(h.value)
            .ok()
            .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|v| v.parse::<usize>().ok())
            .ok_or(reject(400, "invalid Content-Length"))?;
        if length.is_some_and(|l| l != parsed) {
            return Err(reject(400, "conflicting Content-Length"));
        }
        length = Some(parsed);
    }
    let length = length.unwrap_or(0);
    if length > MAX_BODY {
        return Err(reject(413, "body too large"));
    }
    Ok(length)
}

/// Reads until the end of the request head; returns the buffer and the head length.
fn read_head(client: &mut TcpStream) -> Result<(Vec<u8>, usize), Reject> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        let n = client.read(&mut chunk).map_err(|_| reject(408, "request timeout"))?;
        if n == 0 {
            return Err(reject(400, "connection closed before request head"));
        }
        let search_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf[search_from..].windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok((buf, search_from + pos + 4));
        }
        if buf.len() > MAX_HEAD {
            return Err(reject(431, "request head too large"));
        }
    }
}

/// Copies the upstream response to the client until the upstream closes. Returns the status
/// code parsed from the first bytes, for logging only, and the number of bytes relayed.
fn relay(upstream: &mut impl Read, client: &mut impl Write) -> (String, usize) {
    let mut buf = vec![0u8; BUFSIZE];
    let (mut status, mut total) = (String::from("?"), 0usize);
    // A read error also ends the relay: rustls reports a close without close_notify that way.
    while let Ok(n) = upstream.read(&mut buf) {
        if n == 0 {
            break;
        }
        if total == 0 && n >= 12 && buf.starts_with(b"HTTP/1.") {
            status = String::from_utf8_lossy(&buf[9..12]).into_owned();
        }
        if client.write_all(&buf[..n]).and_then(|_| client.flush()).is_err() {
            break;
        }
        total += n;
    }
    (status, total)
}

pub fn reply(stream: &mut impl Write, status: u16, message: &str) -> io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        417 => "Expectation Failed",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let body = format!("{message}\n");
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

pub fn log(message: &str) {
    eprintln!("{message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert!(is_path_allowed("/v1/messages?beta=true"));
        assert!(is_path_allowed("/v1/messages/count_tokens"));
        for p in [
            "/admin", "/v1", "/v1/", "/v1/../x", "/v1/./x", "/v1/%2e%2e/x", "http://e/v1/x",
            "/v1\\x", "/v1//x", "/v1/..;/x", "/v1/x;y",
        ] {
            assert!(!is_path_allowed(p), "{p}");
        }
    }

    #[test]
    fn forwarded_headers() {
        for h in ["Content-Type", "anthropic-version", "X-Stainless-OS", "user-agent"] {
            assert!(is_forwarded(h), "{h}");
        }
        for h in [
            "Host", "Authorization", "x-api-key", "Content-Length", "Connection", "Cookie",
            "X-Original-URL", "X-HTTP-Method-Override", "X-Forwarded-Host",
        ] {
            assert!(!is_forwarded(h), "{h}");
        }
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}
