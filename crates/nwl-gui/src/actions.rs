//! One-click actions on an application, shared by the window, the tray menu
//! and notification buttons, so they all create the same rules.

use nwl_core::api::AppView;
use nwl_core::model::AppId;
use nwl_core::rate::format_bytes;
use serde_json::{json, Value};

/// Limit presets offered in the tray and on notifications, bytes/s.
pub const LIMIT_PRESETS: [u64; 3] = [256_000, 1_000_000, 5_000_000];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuickAction {
    Block,
    Unblock,
    /// Limit download and upload to this many bytes/s.
    Limit(u64),
    RemoveLimit,
}

/// The parts of an app an action needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub app: AppId,
    pub name: String,
    /// The app's one-click block rule, if any.
    pub block_rule: Option<u64>,
    /// The app's one-click limit rule, if any.
    pub limit_rule: Option<u64>,
}

impl From<&AppView> for Target {
    fn from(a: &AppView) -> Self {
        Target {
            app: a.app.clone(),
            name: a.name.clone(),
            block_rule: a.block_rule,
            limit_rule: a.limit_rule,
        }
    }
}

/// An API request carrying out an action.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub method: &'static str,
    pub path: String,
    pub body: Option<Value>,
    /// What to tell the user when it worked.
    pub done: String,
}

/// The request for `action` on `target`, or `None` if there is nothing to
/// do (unblocking an app that is not blocked, ...). An existing one-click
/// rule is updated rather than duplicated.
pub fn request(target: &Target, action: &QuickAction) -> Option<Request> {
    let name = &target.name;
    Some(match action {
        QuickAction::Block if target.block_rule.is_some() => return None,
        QuickAction::Block => Request {
            method: "POST",
            path: "/api/rules".into(),
            body: Some(
                json!({"name": format!("Block {name}"), "match": {"app": target.app}, "action": {"type": "block"}}),
            ),
            done: format!("Blocked {name}"),
        },
        QuickAction::Unblock => Request {
            method: "DELETE",
            path: format!("/api/rules/{}", target.block_rule?),
            body: None,
            done: format!("Unblocked {name}"),
        },
        QuickAction::Limit(rate) => {
            let body = json!({
                "name": format!("Limit {name}"),
                "match": {"app": target.app},
                "action": {"type": "limit", "download": rate, "upload": rate},
            });
            let (method, path) = match target.limit_rule {
                Some(id) => ("PUT", format!("/api/rules/{id}")),
                None => ("POST", "/api/rules".to_string()),
            };
            Request {
                method,
                path,
                body: Some(body),
                done: format!("Limited {name} to {}/s", format_bytes(*rate)),
            }
        }
        QuickAction::RemoveLimit => Request {
            method: "DELETE",
            path: format!("/api/rules/{}", target.limit_rule?),
            body: None,
            done: format!("Removed the limit on {name}"),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(block: Option<u64>, limit: Option<u64>) -> Target {
        Target {
            app: AppId("/usr/bin/rclone".into()),
            name: "rclone".into(),
            block_rule: block,
            limit_rule: limit,
        }
    }

    #[test]
    fn requests() {
        let r = request(&target(None, None), &QuickAction::Block).unwrap();
        assert_eq!((r.method, r.path.as_str()), ("POST", "/api/rules"));
        assert_eq!(r.body.unwrap()["match"]["app"], "/usr/bin/rclone");
        assert_eq!(request(&target(Some(4), None), &QuickAction::Block), None, "already blocked");
        assert_eq!(request(&target(Some(4), None), &QuickAction::Unblock).unwrap().path, "/api/rules/4");
        assert_eq!(request(&target(None, None), &QuickAction::Unblock), None);

        let new = request(&target(None, None), &QuickAction::Limit(1_000_000)).unwrap();
        assert_eq!((new.method, new.done.as_str()), ("POST", "Limited rclone to 1.00 MB/s"));
        let body = new.body.unwrap();
        assert_eq!(
            (body["action"]["download"].as_u64(), body["action"]["upload"].as_u64()),
            (Some(1_000_000), Some(1_000_000))
        );
        let existing = request(&target(None, Some(9)), &QuickAction::Limit(256_000)).unwrap();
        assert_eq!(
            (existing.method, existing.path.as_str()),
            ("PUT", "/api/rules/9"),
            "updates, never duplicates"
        );
        assert_eq!(request(&target(None, None), &QuickAction::RemoveLimit), None);
    }
}
