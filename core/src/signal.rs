//! Клієнт сигналінгу: WebSocket до сервера ZortilWatch (`/signal`). Синхронний
//! (tungstenite), у стилі решти ядра. Типи дзеркалять `server/src/signaling/protocol.ts`
//! (внутрішньо-тегований JSON `{"type": ...}`, поля camelCase, конверт `v:1`).
//!
//! Сервер — «сліпий» брокер: `payload` у `signal` для нього непрозорий (E2E через
//! PAKE-пароль, рішення B1). Тут ми лише доставляємо ці повідомлення між пірами.

use std::net::TcpStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

pub const PROTOCOL_VERSION: u8 = 1;

/// Клієнт -> Сервер.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum ClientMsg {
    #[serde(rename = "register", rename_all = "camelCase")]
    Register {
        v: u8,
        device_id: String,
        client_secret: String,
        client_kind: String,
        /// MAC цього пристрою (щоб його можна було розбудити WoL, PRD 5.9).
        #[serde(skip_serializing_if = "Option::is_none")]
        mac: Option<String>,
        /// Чи може цей пристрій будити інші (надсилати магічний пакет = помічник).
        #[serde(skip_serializing_if = "Option::is_none")]
        can_wake: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rid: Option<String>,
    },
    /// Пульт просить розбудити `target_id` (сервер знайде помічника й передасть).
    #[serde(rename = "wake", rename_all = "camelCase")]
    Wake { v: u8, target_id: String },
    #[serde(rename = "list_presence")]
    ListPresence {
        v: u8,
        ids: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rid: Option<String>,
    },
    #[serde(rename = "connect_request", rename_all = "camelCase")]
    ConnectRequest {
        v: u8,
        target_id: String,
        /// Тип пароля для PAKE на боці керованого: "one_time" | "permanent".
        /// Відсутність (старі клієнти) керований трактує як "permanent".
        #[serde(skip_serializing_if = "Option::is_none")]
        password_kind: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rid: Option<String>,
    },
    #[serde(rename = "connect_accept", rename_all = "camelCase")]
    ConnectAccept { v: u8, session_id: String },
    #[serde(rename = "connect_reject", rename_all = "camelCase")]
    ConnectReject {
        v: u8,
        session_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    #[serde(rename = "signal", rename_all = "camelCase")]
    Signal {
        v: u8,
        session_id: String,
        kind: String,
        payload: Value,
    },
    #[serde(rename = "session_close", rename_all = "camelCase")]
    SessionClose {
        v: u8,
        session_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

impl ClientMsg {
    pub fn register(device_id: &str, client_secret: &str, client_kind: &str) -> Self {
        ClientMsg::Register {
            v: PROTOCOL_VERSION,
            device_id: device_id.to_string(),
            client_secret: client_secret.to_string(),
            client_kind: client_kind.to_string(),
            mac: None,
            can_wake: None,
            rid: None,
        }
    }
    /// Реєстрація з WoL-даними: власний MAC (щоб будили) + чи помічник (будить інші).
    pub fn register_wol(
        device_id: &str,
        client_secret: &str,
        client_kind: &str,
        mac: Option<&str>,
        can_wake: bool,
    ) -> Self {
        ClientMsg::Register {
            v: PROTOCOL_VERSION,
            device_id: device_id.to_string(),
            client_secret: client_secret.to_string(),
            client_kind: client_kind.to_string(),
            mac: mac.map(str::to_string),
            can_wake: Some(can_wake),
            rid: None,
        }
    }
    pub fn wake(target_id: &str) -> Self {
        ClientMsg::Wake {
            v: PROTOCOL_VERSION,
            target_id: target_id.to_string(),
        }
    }
    pub fn connect_request(target_id: &str) -> Self {
        ClientMsg::ConnectRequest {
            v: PROTOCOL_VERSION,
            target_id: target_id.to_string(),
            password_kind: None,
            rid: None,
        }
    }
    pub fn connect_request_kind(target_id: &str, password_kind: &str) -> Self {
        ClientMsg::ConnectRequest {
            v: PROTOCOL_VERSION,
            target_id: target_id.to_string(),
            password_kind: Some(password_kind.to_string()),
            rid: None,
        }
    }
    pub fn connect_accept(session_id: &str) -> Self {
        ClientMsg::ConnectAccept {
            v: PROTOCOL_VERSION,
            session_id: session_id.to_string(),
        }
    }
    pub fn connect_reject(session_id: &str, reason: Option<&str>) -> Self {
        ClientMsg::ConnectReject {
            v: PROTOCOL_VERSION,
            session_id: session_id.to_string(),
            reason: reason.map(str::to_string),
        }
    }
    pub fn list_presence(ids: Vec<String>) -> Self {
        ClientMsg::ListPresence {
            v: PROTOCOL_VERSION,
            ids,
            rid: None,
        }
    }
    pub fn signal(session_id: &str, kind: &str, payload: Value) -> Self {
        ClientMsg::Signal {
            v: PROTOCOL_VERSION,
            session_id: session_id.to_string(),
            kind: kind.to_string(),
            payload,
        }
    }
    pub fn session_close(session_id: &str, reason: Option<&str>) -> Self {
        ClientMsg::SessionClose {
            v: PROTOCOL_VERSION,
            session_id: session_id.to_string(),
            reason: reason.map(str::to_string),
        }
    }
}

/// Сервер -> Клієнт. Невідомі поля ігноруються serde-ом; відсутні `Option` -> `None`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMsg {
    #[serde(rename = "register_ok", rename_all = "camelCase")]
    RegisterOk {
        device_id: String,
        server_time: i64,
        rid: Option<String>,
    },
    #[serde(rename = "register_err")]
    RegisterErr {
        code: String,
        reason: String,
        rid: Option<String>,
    },
    #[serde(rename = "presence_state")]
    PresenceState { entries: Value, rid: Option<String> },
    #[serde(rename = "presence_update")]
    PresenceUpdate {
        id: String,
        online: bool,
        busy: Option<bool>,
    },
    #[serde(rename = "connect_err", rename_all = "camelCase")]
    ConnectErr {
        code: String,
        rid: Option<String>,
        retry_after: Option<u64>,
    },
    #[serde(rename = "incoming_request", rename_all = "camelCase")]
    IncomingRequest {
        session_id: String,
        from_kind: String,
        password_kind: Option<String>,
        ice_servers: Option<Value>,
    },
    #[serde(rename = "connect_ready", rename_all = "camelCase")]
    ConnectReady {
        session_id: String,
        role: String,
        peer_kind: String,
        ice_servers: Option<Value>,
    },
    #[serde(rename = "signal", rename_all = "camelCase")]
    Signal {
        session_id: String,
        kind: String,
        payload: Value,
    },
    #[serde(rename = "session_close", rename_all = "camelCase")]
    SessionClose {
        session_id: String,
        reason: Option<String>,
    },
    /// Сервер -> ПОМІЧНИК: надішли магічний пакет на цей MAC (PRD 5.9).
    #[serde(rename = "wake_dispatch", rename_all = "camelCase")]
    WakeDispatch { mac: String },
    /// Сервер -> ПУЛЬТ: підсумок спроби розбудити (чесний статус, PRD 5.9).
    /// `status`: dispatched | no_helper | unsupported | offline_unknown.
    #[serde(rename = "wake_result", rename_all = "camelCase")]
    WakeResult { status: String, helpers: u32 },
    #[serde(rename = "error")]
    Error {
        code: String,
        reason: String,
        rid: Option<String>,
    },
    /// Невідомий тип повідомлення: нові типи сервера не валять з'єднання клієнта
    /// (decode-помилка в `recv`/`try_recv` трактується як зламаний WS).
    #[serde(other)]
    Unknown,
}

#[derive(Debug)]
pub struct SignalError(pub String);

impl std::fmt::Display for SignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signal error: {}", self.0)
    }
}
impl std::error::Error for SignalError {}

fn err<E: std::fmt::Display>(e: E) -> SignalError {
    SignalError(e.to_string())
}

/// Синхронний WS-клієнт сигналінгу.
pub struct SignalClient {
    ws: WebSocket<MaybeTlsStream<TcpStream>>,
}

impl SignalClient {
    /// Під'єднатися до `ws://.../signal`.
    pub fn connect(url: &str) -> Result<Self, SignalError> {
        let (ws, _resp) = tungstenite::connect(url).map_err(err)?;
        Ok(Self { ws })
    }

    /// Таймаут читання нижчого TCP-сокета (щоб `recv` не висів вічно у тестах).
    pub fn set_read_timeout(&mut self, dur: Option<Duration>) -> Result<(), SignalError> {
        match self.ws.get_ref() {
            MaybeTlsStream::Plain(tcp) => tcp.set_read_timeout(dur).map_err(err),
            _ => Ok(()),
        }
    }

    /// Надіслати повідомлення клієнта.
    pub fn send(&mut self, msg: &ClientMsg) -> Result<(), SignalError> {
        let txt = serde_json::to_string(msg).map_err(err)?;
        self.ws.send(Message::Text(txt)).map_err(err)
    }

    /// Блокувально прочитати наступне серверне повідомлення (контрол-фрейми пропускаються).
    pub fn recv(&mut self) -> Result<ServerMsg, SignalError> {
        loop {
            match self.ws.read().map_err(err)? {
                Message::Text(s) => {
                    return serde_json::from_str::<ServerMsg>(&s)
                        .map_err(|e| SignalError(format!("decode {e}: {s}")));
                }
                Message::Close(_) => return Err(SignalError("connection closed".into())),
                _ => continue, // Ping/Pong/Binary — ігноруємо (tungstenite сам відповідає на Ping)
            }
        }
    }

    /// Прийом без вічного блокування (потребує виставленого `set_read_timeout`):
    /// `Ok(Some(..))` — є повідомлення; `Ok(None)` — даних немає (минув таймаут);
    /// `Err(..)` — з'єднання закрите/зламане. Періодичний виклик також тримає WS
    /// живим: tungstenite відповідає на серверні Ping саме під час читання, без
    /// цього heartbeat сервера термінує сокет.
    pub fn try_recv(&mut self) -> Result<Option<ServerMsg>, SignalError> {
        loop {
            match self.ws.read() {
                Ok(Message::Text(s)) => {
                    return serde_json::from_str::<ServerMsg>(&s)
                        .map(Some)
                        .map_err(|e| SignalError(format!("decode {e}: {s}")));
                }
                Ok(Message::Close(_)) => return Err(SignalError("connection closed".into())),
                Ok(_) => continue, // Ping/Pong/Binary
                Err(tungstenite::Error::Io(ref e))
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(None)
                }
                Err(e) => return Err(err(e)),
            }
        }
    }

    /// Зручний хелпер: register -> чекати register_ok (або помилка).
    pub fn register(
        &mut self,
        device_id: &str,
        client_secret: &str,
        client_kind: &str,
    ) -> Result<(), SignalError> {
        self.send(&ClientMsg::register(device_id, client_secret, client_kind))?;
        self.await_register_ok()
    }

    /// Реєстрація з WoL-даними (власний MAC + чи помічник), потім чекати register_ok.
    pub fn register_wol(
        &mut self,
        device_id: &str,
        client_secret: &str,
        client_kind: &str,
        mac: Option<&str>,
        can_wake: bool,
    ) -> Result<(), SignalError> {
        self.send(&ClientMsg::register_wol(
            device_id,
            client_secret,
            client_kind,
            mac,
            can_wake,
        ))?;
        self.await_register_ok()
    }

    fn await_register_ok(&mut self) -> Result<(), SignalError> {
        match self.recv()? {
            ServerMsg::RegisterOk { .. } => Ok(()),
            ServerMsg::RegisterErr { code, reason, .. } => {
                Err(SignalError(format!("register_err {code}: {reason}")))
            }
            other => Err(SignalError(format!("unexpected after register: {other:?}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_serializes_with_envelope_and_camelcase() {
        let m = ClientMsg::register("559065114", "secret-x", "host");
        let j: Value = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(j["type"], "register");
        assert_eq!(j["v"], 1);
        assert_eq!(j["deviceId"], "559065114");
        assert_eq!(j["clientSecret"], "secret-x");
        assert_eq!(j["clientKind"], "host");
        assert!(j.get("rid").is_none()); // None пропускається
    }

    #[test]
    fn connect_ready_deserializes() {
        let raw = r#"{"v":1,"type":"connect_ready","sessionId":"s1","role":"offerer","peerKind":"controller"}"#;
        match serde_json::from_str::<ServerMsg>(raw).unwrap() {
            ServerMsg::ConnectReady {
                session_id,
                role,
                peer_kind,
                ice_servers,
            } => {
                assert_eq!(session_id, "s1");
                assert_eq!(role, "offerer");
                assert_eq!(peer_kind, "controller");
                assert!(ice_servers.is_none()); // відсутнє поле -> None
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn unknown_server_message_type_is_tolerated() {
        let raw = r#"{"v":1,"type":"future_feature","stuff":42}"#;
        match serde_json::from_str::<ServerMsg>(raw).unwrap() {
            ServerMsg::Unknown => {}
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn signal_payload_is_opaque_roundtrip() {
        let m = ClientMsg::signal("s1", "offer", serde_json::json!({"sdp":"v=0..."}));
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""type":"signal""#));
        assert!(s.contains(r#""kind":"offer""#));
        assert!(s.contains(r#""sdp":"v=0...""#));
    }
}
