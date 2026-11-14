mod config;
mod proxy;
mod upstream;

use std::io::Write;
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

const LISTEN_HOST: &str = "127.0.0.1";
const MAX_CLIENTS: usize = 32;

fn main() -> ExitCode {
    if let Err(e) = deny_memory_dumps() {
        return fail(1, &format!("cannot disable core dumps: {e}"));
    }
    let args = match config::parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => return fail(2, &e),
    };
    let secrets = match config::read_secrets(std::io::stdin().lock()) {
        Ok(secrets) => secrets,
        Err(e) => return fail(2, &e),
    };
    let connector = match upstream::Connector::new() {
        Ok(connector) => connector,
        Err(e) => return fail(1, &e),
    };
    let listener = match TcpListener::bind((LISTEN_HOST, args.port)) {
        Ok(listener) => listener,
        Err(e) => return fail(1, &format!("cannot listen on {LISTEN_HOST}:{}: {e}", args.port)),
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => return fail(1, &format!("cannot read the listening port: {e}")),
    };
    proxy::log(&format!(
        "listening on {LISTEN_HOST}:{port} -> https://{}{}",
        args.upstream.host_header(),
        args.upstream.base_path
    ));
    // The launcher reads the port from here, over a pipe only this process can write to.
    let mut stdout = std::io::stdout().lock();
    if writeln!(stdout, "port={port}").and_then(|_| stdout.flush()).is_err() {
        return fail(1, "cannot report the listening port on stdout");
    }
    drop(stdout);

    let proxy = Arc::new(proxy::Proxy::new(secrets, args.auth, args.upstream, connector));
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
            active.fetch_sub(1, Ordering::SeqCst);
            let _ = proxy::reply(&mut stream, 503, "too many concurrent requests");
            continue;
        }
        let (proxy, active) = (Arc::clone(&proxy), Arc::clone(&active));
        thread::spawn(move || {
            proxy.handle(stream);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    ExitCode::SUCCESS
}

/// Marks the process non-dumpable: no core dump (which a crash handler such as apport would
/// write to disk, token included) and no ptrace or /proc/<pid>/mem access by the same user.
fn deny_memory_dumps() -> std::io::Result<()> {
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes integer arguments only and touches no memory.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn fail(code: u8, message: &str) -> ExitCode {
    proxy::log(&format!("error: {message}"));
    ExitCode::from(code)
}
