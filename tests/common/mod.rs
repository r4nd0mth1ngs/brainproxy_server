//! Shared by the test files: finding the brainproxy CLI, and a small local web app to scan.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// The CLI from `BRAINPROXY_BIN`, or `brainproxy` on PATH. Without one the tests are skipped,
/// unless `BRAINPROXY_CONTRACT=1` is set (CI sets it), when a missing CLI fails them.
pub fn cli() -> Option<PathBuf> {
    let found = std::env::var_os("BRAINPROXY_BIN").map(PathBuf::from).or_else(|| {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).map(|d| d.join("brainproxy")).find(|p| p.is_file())
    });
    if found.is_none() {
        assert!(
            std::env::var("BRAINPROXY_CONTRACT").as_deref() != Ok("1"),
            "BRAINPROXY_CONTRACT=1 but no brainproxy CLI: set BRAINPROXY_BIN"
        );
        eprintln!("skipped: no brainproxy CLI (set BRAINPROXY_BIN)");
    }
    found
}

// ---------------------------------------------------------------------------------------------
// The web app: a reflected XSS that is always there, a SQL error behind `drift`, `pages` plain
// pages, a login, and an optional delay per response.

#[derive(Default)]
pub struct State {
    pub drift: AtomicBool,
    pub pages: AtomicU64,
    pub delay_ms: AtomicU64,
    /// Extra files by path (a JWKS, an ownership file).
    pub files: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

pub struct App {
    pub port: u16,
    pub state: Arc<State>,
}

impl App {
    pub fn start(pages: u64) -> App {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(State::default());
        state.pages.store(pages, Ordering::SeqCst);
        let s = state.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let s = s.clone();
                std::thread::spawn(move || serve(conn, &s));
            }
        });
        App { port, state }
    }

    pub fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn url(&self) -> String {
        format!("http://{}/", self.host())
    }
}

fn serve(conn: TcpStream, state: &State) {
    let mut reader = BufReader::new(conn.try_clone().unwrap());
    let mut conn = conn;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let target = line.split_whitespace().nth(1).unwrap_or("/").to_string();
        let mut length = 0;
        let mut cookie = String::new();
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).unwrap_or(0) == 0 {
                return;
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            let (name, value) = h.split_once(':').unwrap_or((h, ""));
            match name.to_ascii_lowercase().as_str() {
                "content-length" => length = value.trim().parse().unwrap_or(0),
                "cookie" => cookie = value.trim().to_string(),
                _ => {}
            }
        }
        let mut body = vec![0; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let delay = state.delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }
        let (status, extra, page) = route(&target, &String::from_utf8_lossy(&body), &cookie, state);
        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n{extra}\r\n{page}",
            page.len()
        );
        if conn.write_all(resp.as_bytes()).is_err() {
            return;
        }
    }
}

fn route(target: &str, body: &str, cookie: &str, state: &State) -> (&'static str, String, String) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let param = |name: &str| {
        query.split('&').find_map(|kv| kv.strip_prefix(&format!("{name}="))).map(decode).unwrap_or_default()
    };
    let html = |inner: String| format!("<html><head><title>app</title></head><body>{inner}</body></html>");
    if let Some(f) = state.files.lock().unwrap().get(path) {
        return ("200 OK", String::new(), f.clone());
    }
    match path {
        "/" => {
            let mut links = String::from("<a href=\"/search?q=hello\">search</a>");
            for i in 0..state.pages.load(Ordering::SeqCst) {
                links.push_str(&format!(" <a href=\"/page/{i}\">page {i}</a>"));
            }
            if state.drift.load(Ordering::SeqCst) {
                links.push_str(" <a href=\"/item?id=1\">item</a>");
            }
            ("200 OK", String::new(), html(links))
        }
        "/search" => ("200 OK", String::new(), html(format!("<p>Results for {}</p>", param("q")))),
        "/item" if state.drift.load(Ordering::SeqCst) => {
            let id = param("id");
            if id.contains('\'') || id.contains('"') {
                let msg = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version";
                ("500 Internal Server Error", String::new(), html(format!("<p>{msg}</p>")))
            } else {
                ("200 OK", String::new(), html(format!("<p>item {}</p>", id.len())))
            }
        }
        p if p.starts_with("/page/") => ("200 OK", String::new(), html("<p>a page</p>".into())),
        "/login" => {
            if body.contains("password=right") {
                ("200 OK", "Set-Cookie: session=ok; Path=/\r\n".into(), html("<p>welcome</p>".into()))
            } else {
                ("403 Forbidden", String::new(), html("<p>no</p>".into()))
            }
        }
        "/me" if cookie.contains("session=ok") => ("200 OK", String::new(), html("<p>logged in as ci</p>".into())),
        "/me" => ("200 OK", String::new(), html("<p>please log in</p>".into())),
        _ => ("404 Not Found", String::new(), html("<p>not found</p>".into())),
    }
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
