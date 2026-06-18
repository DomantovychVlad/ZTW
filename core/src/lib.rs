//! ZortilWatch core — спільне ядро для всіх платформ.
//!
//! Каркас + перші модулі Етапу 2: наскрізне крипто (PAKE) та ідентичність пристрою.
//! Решта (захоплення екрана, кодування, ввід, мережа на str0m) додається далі згідно
//! з docs/architecture.md.

// ── Чиста поверхня (wasm-safe): крипто, протокол сесії, фреймінг медіа ──
// Реюзається веб-клієнтом через WASM — без мережі/ОС-залежностей.
pub mod crypto;
pub mod media;
pub mod session;

// ── Нативна поверхня (мережа/ОС): за фічею "native" (default), поза wasm ──
#[cfg(feature = "native")]
pub mod blank;
#[cfg(feature = "native")]
pub mod capture;
#[cfg(feature = "native")]
pub mod clipboard;
#[cfg(feature = "native")]
pub mod connect;
#[cfg(feature = "native")]
pub mod connection;
#[cfg(feature = "native")]
pub mod encode;
#[cfg(feature = "native")]
pub mod files;
#[cfg(feature = "native")]
pub mod identity;
#[cfg(feature = "native")]
pub mod input;
#[cfg(feature = "native")]
pub mod net;
#[cfg(feature = "native")]
pub mod password;
#[cfg(feature = "native")]
pub mod relay;
#[cfg(feature = "native")]
pub mod signal;
#[cfg(feature = "native")]
pub mod wol;

/// Версія ядра (синхронізована з Cargo).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Стабільна назва продукту.
pub fn product() -> &'static str {
    "ZortilWatch"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_name_is_stable() {
        assert_eq!(product(), "ZortilWatch");
    }

    #[test]
    fn version_is_non_empty() {
        assert!(!VERSION.is_empty());
    }
}
