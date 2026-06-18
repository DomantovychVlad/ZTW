//! Стратегія встановлення з'єднання «спершу напряму, ретранслятор як запас» (E1).
//!
//! Чиста політика часу: коли додавати relay-кандидати (TURN), а коли здаватися.
//! Власне ICE (host/srflx/relay) робить str0m; тут — лише рішення про escalation,
//! щоб логіку можна було повністю покрити тестами окремо від мережі.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackAction {
    /// Продовжувати спроби прямого з'єднання.
    KeepTrying,
    /// Додати relay-кандидати (TURN) — прямий канал не піднявся вчасно.
    AddRelay,
    /// З'єднання встановлено.
    Connected,
    /// Вичерпано час — невдача.
    GiveUp,
}

/// Часова політика переходу на ретранслятор.
#[derive(Debug, Clone, Copy)]
pub struct FallbackPolicy {
    /// Скільки пробувати напряму до додавання relay.
    pub relay_after: Duration,
    /// Після цього часу без з'єднання — здатися.
    pub give_up_after: Duration,
}

impl Default for FallbackPolicy {
    fn default() -> Self {
        Self {
            relay_after: Duration::from_secs(3),
            give_up_after: Duration::from_secs(12),
        }
    }
}

impl FallbackPolicy {
    /// Рішення стратегії за поточним станом ICE та часом від початку спроби.
    pub fn decide(
        &self,
        elapsed: Duration,
        ice_connected: bool,
        relay_added: bool,
    ) -> FallbackAction {
        if ice_connected {
            FallbackAction::Connected
        } else if elapsed >= self.give_up_after {
            FallbackAction::GiveUp
        } else if elapsed >= self.relay_after && !relay_added {
            FallbackAction::AddRelay
        } else {
            FallbackAction::KeepTrying
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_short_circuits_regardless_of_time() {
        let p = FallbackPolicy::default();
        assert_eq!(
            p.decide(Duration::from_secs(0), true, false),
            FallbackAction::Connected
        );
        assert_eq!(
            p.decide(Duration::from_secs(100), true, true),
            FallbackAction::Connected
        );
    }

    #[test]
    fn tries_direct_first() {
        let p = FallbackPolicy::default();
        assert_eq!(
            p.decide(Duration::from_secs(1), false, false),
            FallbackAction::KeepTrying
        );
    }

    #[test]
    fn escalates_to_relay_after_timeout_then_waits() {
        let p = FallbackPolicy::default();
        assert_eq!(
            p.decide(Duration::from_secs(4), false, false),
            FallbackAction::AddRelay
        );
        // Relay вже додано -> просто чекаємо далі.
        assert_eq!(
            p.decide(Duration::from_secs(5), false, true),
            FallbackAction::KeepTrying
        );
    }

    #[test]
    fn gives_up_after_deadline() {
        let p = FallbackPolicy::default();
        assert_eq!(
            p.decide(Duration::from_secs(13), false, true),
            FallbackAction::GiveUp
        );
    }
}
