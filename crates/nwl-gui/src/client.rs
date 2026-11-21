//! Client for the daemon API.
//!
//! The same async interface on both targets: on the desktop the requests are
//! blocking (`ureq`, run on the poller thread); in the browser they use
//! `fetch`.

use serde::de::DeserializeOwned;
use serde_json::Value;

/// Percent-encodes a query parameter value.
pub fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The error message of a failed response: the daemon's own, when it has one.
fn status_error(code: u16, body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(String::from))
        .unwrap_or_else(|| format!("daemon returned {code}"))
}

#[derive(Clone)]
pub struct Client {
    base: String,
    #[cfg(not(target_arch = "wasm32"))]
    agent: ureq::Agent,
}

impl Client {
    pub fn base(&self) -> &str {
        &self.base
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let value = self.call("GET", path, None).await?;
        serde_json::from_value(value).map_err(|e| format!("unexpected response from {path}: {e}"))
    }

    /// A binary response (icons) and its content type.
    pub async fn get_bytes(&self, path: &str) -> Result<(Vec<u8>, String), String> {
        self.fetch_bytes(path).await
    }

    /// Sends a request; errors carry the daemon's message when it has one.
    pub async fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        let text = self.request(method, path, body).await?;
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Client {
    pub fn new(base: &str) -> Self {
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(5)).build();
        Self { base: base.trim_end_matches('/').to_string(), agent }
    }

    /// A response body as text (blocking; for CSV downloads).
    pub fn get_text(&self, path: &str) -> Result<String, String> {
        pollster::block_on(self.request("GET", path, None))
    }

    async fn fetch_bytes(&self, path: &str) -> Result<(Vec<u8>, String), String> {
        match self.agent.get(&format!("{}{path}", self.base)).call() {
            Ok(r) => {
                let kind = r.content_type().to_string();
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut std::io::Read::take(r.into_reader(), 4 << 20), &mut bytes)
                    .map_err(|e| e.to_string())?;
                Ok((bytes, kind))
            }
            Err(ureq::Error::Status(code, _)) => Err(format!("daemon returned {code}")),
            Err(e) => Err(format!("cannot reach nwld at {}: {e}", self.base)),
        }
    }

    async fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<String, String> {
        let req = self.agent.request(method, &format!("{}{path}", self.base)).set("x-nwl-client", "desktop");
        let resp = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match resp {
            Ok(r) => r.into_string().map_err(|e| e.to_string()),
            Err(ureq::Error::Status(code, r)) => {
                Err(status_error(code, &r.into_string().unwrap_or_default()))
            }
            Err(e) => Err(format!("cannot reach nwld at {}: {e}", self.base)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl Client {
    /// A client for the daemon that served this page.
    pub fn same_origin() -> Self {
        let base = web_sys::window().and_then(|w| w.location().origin().ok()).unwrap_or_default();
        Self { base }
    }

    async fn fetch_bytes(&self, path: &str) -> Result<(Vec<u8>, String), String> {
        use wasm_bindgen::JsCast;
        use wasm_bindgen_futures::JsFuture;
        let failed = |e: wasm_bindgen::JsValue| format!("fetching {path}: {e:?}");
        let window = web_sys::window().ok_or("no window")?;
        let url = format!("{}{path}", self.base);
        let resp: web_sys::Response =
            JsFuture::from(window.fetch_with_str(&url)).await.map_err(failed)?.unchecked_into();
        if !resp.ok() {
            return Err(format!("daemon returned {}", resp.status()));
        }
        let kind = resp.headers().get("content-type").ok().flatten().unwrap_or_default();
        let buffer = JsFuture::from(resp.array_buffer().map_err(failed)?).await.map_err(failed)?;
        Ok((js_sys::Uint8Array::new(&buffer).to_vec(), kind))
    }

    async fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<String, String> {
        use wasm_bindgen::JsCast;
        use wasm_bindgen_futures::JsFuture;
        let unreachable = |e: wasm_bindgen::JsValue| format!("cannot reach nwld at {}: {e:?}", self.base);

        let headers = web_sys::Headers::new().map_err(unreachable)?;
        headers.set("x-nwl-client", "web").map_err(unreachable)?;
        let init = web_sys::RequestInit::new();
        init.set_method(method);
        if let Some(b) = body {
            headers.set("content-type", "application/json").map_err(unreachable)?;
            init.set_body(&wasm_bindgen::JsValue::from_str(&b.to_string()));
        }
        init.set_headers(&headers);
        let url = format!("{}{path}", self.base);
        let request = web_sys::Request::new_with_str_and_init(&url, &init).map_err(unreachable)?;
        let window = web_sys::window().ok_or("no window")?;
        let resp: web_sys::Response =
            JsFuture::from(window.fetch_with_request(&request)).await.map_err(unreachable)?.unchecked_into();
        let text = JsFuture::from(resp.text().map_err(unreachable)?).await.map_err(unreachable)?;
        let text = text.as_string().unwrap_or_default();
        if resp.ok() {
            Ok(text)
        } else {
            Err(status_error(resp.status(), &text))
        }
    }
}

/// Waits without blocking the browser.
#[cfg(target_arch = "wasm32")]
pub async fn sleep(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}
