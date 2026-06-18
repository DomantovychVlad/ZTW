//! Встановлення захищеної сесії (рішення B1, PRD 5.1/5.10).
//!
//! Поверх уже піднятого WebRTC-каналу два піри виконують PAKE на паролі підключення,
//! виводять спільний сесійний ключ і ПІДТВЕРДЖУЮТЬ його прив'язкою до DTLS-відбитків
//! обох сторін. Якщо паролі різні АБО сигналінг-сервер підмінив відбиток (MITM) —
//! прив'язки не збігаються, і сесія відхиляється.
//!
//! Тут — чистий стейт-машина рукостискання (повідомлення туди-сюди), щоб логіку можна
//! було повністю покрити тестами без мережі. Серіалізація на канал — окремо.

#[cfg(feature = "native")]
use crate::crypto::pake_start;
use crate::crypto::{pake_finish, pake_start_with_rng, session_binding, PakeState};
use serde::{Deserialize, Serialize};

/// Повідомлення рукостискання сесії, що йдуть каналом.
#[derive(Serialize, Deserialize)]
pub enum SessionMessage {
    /// Вихідне PAKE-повідомлення.
    Pake(Vec<u8>),
    /// Тег підтвердження = прив'язка ключа до DTLS-відбитків.
    Binding([u8; 32]),
}

enum State {
    AwaitingPake(PakeState),
    AwaitingBinding { key: [u8; 32], my_binding: [u8; 32] },
    Confirmed([u8; 32]),
    Failed,
}

/// Рукостискання сесії на одній стороні.
pub struct Handshake {
    own_fp: String,
    peer_fp: String,
    state: State,
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

impl Handshake {
    /// Почати рукостискання (OsRng). `own_fp`/`peer_fp` — DTLS-відбитки (свій і піра, як їх
    /// бачили в SDP). Повертає себе й перше PAKE-повідомлення для відправки піру.
    #[cfg(feature = "native")]
    pub fn start(password: &[u8], own_fp: String, peer_fp: String) -> (Self, SessionMessage) {
        let (pake, msg) = pake_start(password);
        Self::from_pake(pake, msg, own_fp, peer_fp)
    }

    /// Те саме, але з ЯВНИМ CSPRNG — для wasm-пульта (браузерний ChaCha20Rng, без OsRng).
    pub fn start_with_rng(
        password: &[u8],
        own_fp: String,
        peer_fp: String,
        rng: impl rand_core::CryptoRng + rand_core::RngCore,
    ) -> (Self, SessionMessage) {
        let (pake, msg) = pake_start_with_rng(password, rng);
        Self::from_pake(pake, msg, own_fp, peer_fp)
    }

    fn from_pake(
        pake: PakeState,
        msg: Vec<u8>,
        own_fp: String,
        peer_fp: String,
    ) -> (Self, SessionMessage) {
        (
            Self {
                own_fp,
                peer_fp,
                state: State::AwaitingPake(pake),
            },
            SessionMessage::Pake(msg),
        )
    }

    /// Обробити вхідне повідомлення; за потреби повертає відповідь для відправки.
    pub fn on_message(&mut self, msg: SessionMessage) -> Option<SessionMessage> {
        let state = std::mem::replace(&mut self.state, State::Failed);
        match (state, msg) {
            (State::AwaitingPake(pake), SessionMessage::Pake(inbound)) => {
                match pake_finish(pake, &inbound) {
                    Ok(key) => {
                        let my_binding = session_binding(&key, &self.own_fp, &self.peer_fp);
                        self.state = State::AwaitingBinding { key, my_binding };
                        Some(SessionMessage::Binding(my_binding))
                    }
                    Err(_) => {
                        self.state = State::Failed;
                        None
                    }
                }
            }
            (State::AwaitingBinding { key, my_binding }, SessionMessage::Binding(peer_binding)) => {
                self.state = if ct_eq(&my_binding, &peer_binding) {
                    State::Confirmed(key)
                } else {
                    State::Failed
                };
                None
            }
            _ => {
                self.state = State::Failed;
                None
            }
        }
    }

    /// Сесійний ключ, якщо рукостискання підтверджено.
    pub fn confirmed_key(&self) -> Option<&[u8; 32]> {
        match &self.state {
            State::Confirmed(k) => Some(k),
            _ => None,
        }
    }

    pub fn is_confirmed(&self) -> bool {
        matches!(self.state, State::Confirmed(_))
    }

    pub fn is_failed(&self) -> bool {
        matches!(self.state, State::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_A: &str = "AA:AA:AA";
    const FP_B: &str = "BB:BB:BB";
    const FP_EVIL: &str = "EE:EE:EE";

    /// Прогнати повний обмін між двома сторонами; повертає (A, B).
    fn run(pw_a: &[u8], pw_b: &[u8], a_peer_fp: &str, b_peer_fp: &str) -> (Handshake, Handshake) {
        let (mut a, a_pake) = Handshake::start(pw_a, FP_A.into(), a_peer_fp.into());
        let (mut b, b_pake) = Handshake::start(pw_b, FP_B.into(), b_peer_fp.into());

        // Обмін PAKE -> кожен виводить ключ і повертає свій binding.
        let a_bind = a.on_message(b_pake);
        let b_bind = b.on_message(a_pake);

        // Обмін binding -> підтвердження.
        if let Some(m) = b_bind {
            a.on_message(m);
        }
        if let Some(m) = a_bind {
            b.on_message(m);
        }
        (a, b)
    }

    #[test]
    fn same_password_correct_fps_confirms_both_with_same_key() {
        let (a, b) = run(b"hunter2", b"hunter2", FP_B, FP_A);
        assert!(a.is_confirmed() && b.is_confirmed());
        assert_eq!(a.confirmed_key(), b.confirmed_key());
    }

    #[test]
    fn wrong_password_fails_both() {
        let (a, b) = run(b"hunter2", b"wrong", FP_B, FP_A);
        assert!(a.is_failed() && b.is_failed());
        assert!(a.confirmed_key().is_none());
    }

    #[test]
    fn mitm_swapped_fingerprint_is_detected() {
        // Пароль правильний (MITM ретранслює PAKE), але A бачить підмінений відбиток піра.
        let (a, b) = run(b"hunter2", b"hunter2", FP_EVIL, FP_A);
        assert!(a.is_failed() && b.is_failed());
    }
}
