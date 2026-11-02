//! The read-only results page (research PLAN, phase 3): one HTML page, its script and its style,
//! compiled in. They hold no data and need no token; the page asks for one and calls the JSON API
//! with it, so it shows exactly what that token may read.

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// Only this origin's own script, style and API; nothing inline, no frames, no forms.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const INDEX: &str = include_str!("ui/index.html");
const SCRIPT: &str = include_str!("ui/app.js");
const STYLE: &str = include_str!("ui/app.css");

/// `GET /ui`, `/ui/app.js` and `/ui/app.css`, for either listener's router.
pub fn routes<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route("/ui", get(|| async { file(INDEX, "text/html; charset=utf-8") }))
        .route("/ui/app.js", get(|| async { file(SCRIPT, "text/javascript; charset=utf-8") }))
        .route("/ui/app.css", get(|| async { file(STYLE, "text/css; charset=utf-8") }))
}

fn file(body: &'static str, content_type: &'static str) -> Response {
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_carry_the_security_headers() {
        for (body, ty) in [(INDEX, "text/html"), (SCRIPT, "text/javascript"), (STYLE, "text/css")] {
            let r = file(body, if ty == "text/html" { "text/html; charset=utf-8" } else { ty });
            let h = r.headers();
            assert!(h[header::CONTENT_TYPE].to_str().unwrap().starts_with(ty));
            assert_eq!(h[header::CONTENT_SECURITY_POLICY], CSP);
            assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
            assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
            assert_eq!(h[header::CACHE_CONTROL], "no-store");
        }
    }

    /// The CSP forbids inline script and style, and data must never reach the DOM as HTML.
    #[test]
    fn nothing_inline_and_no_html_from_data() {
        assert!(!INDEX.contains("<style") && !INDEX.contains(" style="));
        // No event handler attributes (` onclick=` and the like).
        assert!(!INDEX.split(" on").skip(1).any(|rest| {
            let name: String = rest.chars().take_while(char::is_ascii_lowercase).collect();
            !name.is_empty() && rest[name.len()..].starts_with('=')
        }));
        assert_eq!(INDEX.matches("<script").count(), 1);
        assert!(INDEX.contains("<script src=\"/ui/app.js\"></script>"));
        for bad in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "localStorage"] {
            assert!(!SCRIPT.contains(bad), "app.js uses {bad}");
        }
    }
}
