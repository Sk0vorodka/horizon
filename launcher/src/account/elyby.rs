//! The ely.by account sign-in (docs.ely.by, "Authentication for Minecraft"): the Yggdrasil
//! protocol's authenticate and refresh against `https://authserver.ely.by`. Secrets (the
//! access token, the client token) live in the OS keychain like the Microsoft accounts';
//! accounts.json keeps only the name and UUID. The game gets the same session file the
//! Microsoft accounts get, with `user_type: "elyby"`.
//!
//! Two-factor accounts answer the authenticate call with 401 "Account protected with two
//! factor auth."; the launcher asks for the code and retries with `password:token`.
//!
//! Ely.by accounts are their own kind of owner: ely.by is an alternative account service for
//! players without a Microsoft account, and its sessions play the same way the Microsoft ones
//! do. The Mojang download of the game files still needs a Microsoft owner: the launcher never
//! hands out Mojang's files itself.
use serde_json::{json, Value};
use std::time::Duration;

use super::{Account, AccountKind, Secrets};

/// The ely.by authserver (the authlib-injector `ely.by` metadata's base).
pub const AUTHSERVER: &str = "https://authserver.ely.by";
/// An environment override for the client token (tests use it; the launcher's own
/// client token is one per install, kept in `data_dir/ely-client-token`).
pub const CLIENT_TOKEN_ENV: &str = "HORIZON_ELYBY_CLIENT_TOKEN";
/// Where a new account is made, shown beside the sign-in fields.
pub const REGISTER_URL: &str = "https://account.ely.by/register";
/// The error a two-factor account's first sign-in answers with: the code is wanted.
pub const NEEDS_TOTP: &str = "This ely.by account is protected with two-factor authentication. Enter the 6-digit code from your authenticator app.";

/// A request to `url`: the launcher's user agent, a 20 s timeout, and the player's proxy when
/// one is set, like the Microsoft sign-in's requests.
fn request_to(method: &str, url: &str) -> ureq::Request {
    crate::proxy::agent(
        ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(20))
            .user_agent(&format!("horizon-launcher/{}", crate::backend::VERSION)),
        url,
    )
    .build()
    .request(method, url)
}

fn send(url: &str, body: Value) -> Result<(u16, Value), String> {
    let response = match request_to("POST", url)
        .set("Content-Type", "application/json; charset=utf-8")
        .send_json(body)
    {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(ureq::Error::Transport(_)) => {
            return Err("Could not reach ely.by. Check your internet connection.".into())
        }
    };
    let status = response.status();
    let text = response.into_string().unwrap_or_default();
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// What a sign-in is waiting for, as the window shows it.
#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    /// The fields are in: asking ely.by.
    Starting,
    /// 401 with "Account protected with two factor auth.": the 6-digit code is wanted.
    Totp,
    Done(Result<(Account, Secrets), String>),
}

/// The authenticate response's profile: the account and the secrets to keep.
fn response_profile(v: &Value) -> Result<(Account, Secrets), String> {
    let Some(token) = str_field(v, "accessToken").filter(|t| !t.is_empty()) else {
        return Err("ely.by did not return an access token.".into());
    };
    let client = str_field(v, "clientToken").unwrap_or_default();
    let Some(p) = v.get("selectedProfile").or_else(|| {
        v.get("availableProfiles")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
    }) else {
        return Err("This ely.by account has no Minecraft profile yet.".into());
    };
    let (Some(uuid), Some(name)) = (str_field(p, "id"), str_field(p, "name")) else {
        return Err("Could not read the ely.by profile.".into());
    };
    Ok((
        Account {
            uuid: uuid.replace('-', "").to_lowercase(),
            name,
            skin: None,
            cape: None,
            kind: AccountKind::Elyby,
        },
        Secrets::elyby(token, client),
    ))
}

/// POST /auth/authenticate. `totp` is the six-digit code when the account asked for one
/// (sent as `password:token`, the protocol's way with Yggdrasil servers).
pub fn authenticate(
    username: &str,
    password: &str,
    totp: Option<&str>,
    client_token: &str,
) -> Result<(Account, Secrets), String> {
    let password = match totp {
        Some(code) if !code.is_empty() => format!("{password}:{code}"),
        _ => password.to_owned(),
    };
    let (status, v) = send(
        &format!("{AUTHSERVER}/auth/authenticate"),
        json!({
            "username": username.trim(),
            "password": password,
            "clientToken": client_token,
            "requestUser": true,
        }),
    )?;
    match status {
        200 => response_profile(&v),
        // The case the player can act on; anything else is the protocol's error text.
        401 if v.get("errorMessage").and_then(Value::as_str)
            == Some("Account protected with two factor auth.") =>
        {
            Err(NEEDS_TOTP.into())
        }
        _ => Err(elyby_error(&v, "ely.by refused the sign-in.")),
    }
}

/// The protocol's `{error, errorMessage}` as a message for the player.
fn elyby_error(v: &Value, fallback: &str) -> String {
    match v.get("errorMessage").and_then(Value::as_str) {
        Some(m) if !m.is_empty() => m.to_owned(),
        _ => fallback.to_owned(),
    }
}

/// POST /auth/refresh: a new access token for the same client token. An error means the
/// player signs in again (the caller falls back to `authenticate`).
pub fn refresh(secrets: &Secrets) -> Result<Secrets, String> {
    let (status, v) = send(
        &format!("{AUTHSERVER}/auth/refresh"),
        json!({
            "accessToken": secrets.minecraft_token,
            "clientToken": secrets.ely_client_token().unwrap_or_default(),
            "requestUser": true,
        }),
    )?;
    if status != 200 {
        return Err(elyby_error(&v, "ely.by refused to renew the session."));
    }
    let Some(token) = str_field(&v, "accessToken").filter(|t| !t.is_empty()) else {
        return Err("ely.by did not return an access token.".into());
    };
    Ok(Secrets {
        minecraft_token: token,
        ..secrets.clone()
    })
}

/// POST /auth/invalidate: the token leaves ely.by's store (sign out). Nothing when it was
/// already gone, as the protocol wants.
pub fn invalidate(secrets: &Secrets) {
    let _ = send(
        &format!("{AUTHSERVER}/auth/invalidate"),
        json!({
            "accessToken": secrets.minecraft_token,
            "clientToken": secrets.ely_client_token().unwrap_or_default(),
        }),
    );
}

/// A sign-in on its own thread, from the fields to the saved account. The window shows
/// `state()`; a Totp step makes it show the code field.
pub struct SignIn {
    state: std::sync::Arc<std::sync::Mutex<Step>>,
    username: String,
    password: String,
}

impl SignIn {
    pub fn start(username: String, password: String, client_token: String) -> Self {
        let state = std::sync::Arc::new(std::sync::Mutex::new(Step::Starting));
        let thread_state = state.clone();
        let thread_username = username.clone();
        let thread_password = password.clone();
        std::thread::spawn(move || {
            let set = |s| *thread_state.lock().unwrap() = s;
            let result = authenticate(&thread_username, &thread_password, None, &client_token);
            if matches!(&result, Err(e) if e == NEEDS_TOTP) {
                set(Step::Totp);
                return;
            }
            set(Step::Done(result));
        });
        Self {
            state,
            username,
            password,
        }
    }
    /// The retry with the code, after the player typed it.
    pub fn submit_totp(&self, code: String, client_token: String) {
        let state = self.state.clone();
        let (username, password) = (self.username.clone(), self.password.clone());
        std::thread::spawn(move || {
            let result = authenticate(&username, &password, Some(&code), &client_token);
            *state.lock().unwrap() = Step::Done(result);
        });
    }
    pub fn state(&self) -> Step {
        self.state.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_body() -> Value {
        json!({
            "accessToken": "ely-token",
            "clientToken": "client-1",
            "availableProfiles": [
                {"id": "069a79f444e94726a5befca90e38aaf5", "name": "Notch"}
            ],
            "selectedProfile": {"id": "069a79f444e94726a5befca90e38aaf5", "name": "Notch"},
            "user": {"id": "u", "username": "mail@example.com"}
        })
    }

    #[test]
    fn response_profiles() {
        let (account, secrets) = response_profile(&profile_body()).unwrap();
        assert_eq!(account.name, "Notch");
        assert_eq!(account.uuid, "069a79f444e94726a5befca90e38aaf5");
        assert_eq!(account.kind, AccountKind::Elyby);
        assert_eq!(secrets.minecraft_token, "ely-token");
        assert_eq!(secrets.ely_client_token(), Some("client-1"));
        // No selectedProfile: the first available one plays.
        let mut v = profile_body();
        v.as_object_mut().unwrap().remove("selectedProfile");
        let (account, _) = response_profile(&v).unwrap();
        assert_eq!(account.name, "Notch");
        // No profile at all: an error.
        let mut v = profile_body();
        v.as_object_mut().unwrap().remove("availableProfiles");
        v.as_object_mut().unwrap().remove("selectedProfile");
        assert!(response_profile(&v).is_err());
        // No token: an error.
        let mut v = profile_body();
        v.as_object_mut().unwrap().remove("accessToken");
        assert!(response_profile(&v).is_err());
    }

    #[test]
    fn secrets_never_show_tokens() {
        let (_, secrets) = response_profile(&profile_body()).unwrap();
        assert!(!format!("{secrets:?}").contains("ely-token"));
    }
}
