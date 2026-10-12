//! Blocking client for the daemon API.

use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::Duration;

#[derive(Clone)]
pub struct Client {
    base: String,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(base: &str) -> Self {
        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(5)).build();
        Self { base: base.trim_end_matches('/').to_string(), agent }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let value = self.call("GET", path, None)?;
        serde_json::from_value(value).map_err(|e| format!("unexpected response from {path}: {e}"))
    }

    /// Sends a request; errors carry the daemon's message when it has one.
    pub fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        let req = self.agent.request(method, &format!("{}{path}", self.base)).set("x-nwl-client", "desktop");
        let resp = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match resp {
            Ok(r) => Ok(r.into_json().unwrap_or(Value::Null)),
            Err(ureq::Error::Status(code, r)) => {
                let body: Value = r.into_json().unwrap_or(Value::Null);
                Err(body["error"].as_str().map_or_else(|| format!("daemon returned {code}"), String::from))
            }
            Err(e) => Err(format!("cannot reach nwld at {}: {e}", self.base)),
        }
    }
}
