//! WASM-обгортка крипто/протокольної поверхні ядра для браузерного пульта (Етап 10).
//!
//! Реюзає ТОЧНО ті ж `crypto`/`session`/`media`, що нативний керований, — тож PAKE-протокол,
//! напрямкові ключі (HKDF-label), формат `[nonce|ct+tag]` і чанкінг медіа збігаються побайтно.
//! Браузер грає роль ВІДПОВІДАЧА WebRTC; це лише крипто-ядро поверх datachannel, мережу/SDP
//! робить браузерний `RTCPeerConnection` (див. `ui/src/platform/web.ts`).
//!
//! Шлях A до getrandom: PAKE стартує через `start_with_rng` з `ChaCha20Rng`, засіяним 32
//! байтами з `crypto.getRandomValues` — жодного браузерного getrandom-бекенда не треба.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use wasm_bindgen::prelude::*;
use zortilwatch_core::crypto::{
    StreamOpener, StreamSealer, STREAM_LABEL_INPUT_C2H, STREAM_LABEL_MEDIA_H2C,
};
use zortilwatch_core::media::Reassembler;
use zortilwatch_core::session::{Handshake, SessionMessage};

#[wasm_bindgen(start)]
pub fn start() {
    #[cfg(feature = "panic-hook")]
    console_error_panic_hook::set_once();
}

/// PAKE-рукостискання поверх datachannel «session». JS драйвить так:
/// `new(...)` → `firstMessage()` надіслати; кожне вхідне ДО підтвердження → `onMessage(bytes)`
/// (відповідь, якщо є, надіслати; помилка = це медіа, що випередило підтвердження — відкласти);
/// коли `isConfirmed()` → збудувати `videoOpener()`/`inputSealer()`.
#[wasm_bindgen]
pub struct WasmHandshake {
    inner: Handshake,
    first: Vec<u8>,
}

#[wasm_bindgen]
impl WasmHandshake {
    /// `password` — пароль підключення; `own_fp`/`peer_fp` — DTLS-відбитки (свій із
    /// localDescription, піра з remoteDescription) у форматі рядка після `a=fingerprint:`
    /// (напр. `"sha-256 AB:CD:…"`), для session_binding; `seed32` — 32 байти CSPRNG.
    #[wasm_bindgen(constructor)]
    pub fn new(
        password: &[u8],
        own_fp: &str,
        peer_fp: &str,
        seed32: &[u8],
    ) -> Result<WasmHandshake, JsError> {
        if seed32.len() < 32 {
            return Err(JsError::new("seed must be >= 32 bytes"));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed32[..32]);
        let rng = ChaCha20Rng::from_seed(seed);
        let (inner, first_msg) =
            Handshake::start_with_rng(password, own_fp.to_string(), peer_fp.to_string(), rng);
        let first = serde_json::to_vec(&first_msg).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(WasmHandshake { inner, first })
    }

    /// Перше PAKE-повідомлення — надіслати по каналу одразу після відкриття.
    #[wasm_bindgen(js_name = firstMessage)]
    pub fn first_message(&self) -> Box<[u8]> {
        self.first.clone().into_boxed_slice()
    }

    /// Подати вхідне повідомлення каналу під час рукостискання. Якщо це session-повідомлення —
    /// обробити й, за потреби, повернути відповідь (надіслати її); якщо НЕ session (медіа, що
    /// випередило підтвердження) — `Err`, і викликач має відкласти ці байти до завершення PAKE.
    #[wasm_bindgen(js_name = onMessage)]
    pub fn on_message(&mut self, data: &[u8]) -> Result<Option<Box<[u8]>>, JsError> {
        let msg: SessionMessage =
            serde_json::from_slice(data).map_err(|_| JsError::new("not-session-message"))?;
        match self.inner.on_message(msg) {
            Some(resp) => {
                let bytes = serde_json::to_vec(&resp).map_err(|e| JsError::new(&e.to_string()))?;
                Ok(Some(bytes.into_boxed_slice()))
            }
            None => Ok(None),
        }
    }

    /// Чи підтверджено сесійний ключ обома сторонами.
    #[wasm_bindgen(js_name = isConfirmed)]
    pub fn is_confirmed(&self) -> bool {
        self.inner.confirmed_key().is_some()
    }

    /// Розшифрувальник відео (керований→пульт). Викликати ПІСЛЯ `isConfirmed()`.
    #[wasm_bindgen(js_name = videoOpener)]
    pub fn video_opener(&self) -> Result<WasmOpener, JsError> {
        let key = self
            .inner
            .confirmed_key()
            .ok_or_else(|| JsError::new("key not confirmed"))?;
        Ok(WasmOpener {
            inner: StreamOpener::new(key, STREAM_LABEL_MEDIA_H2C),
        })
    }

    /// Шифрувальник вводу (пульт→керований). Викликати ПІСЛЯ `isConfirmed()`.
    #[wasm_bindgen(js_name = inputSealer)]
    pub fn input_sealer(&self) -> Result<WasmSealer, JsError> {
        let key = self
            .inner
            .confirmed_key()
            .ok_or_else(|| JsError::new("key not confirmed"))?;
        Ok(WasmSealer {
            inner: StreamSealer::new(key, STREAM_LABEL_INPUT_C2H),
        })
    }
}

/// Шифрувальник вводу: подія (JSON-байти) → `[nonce|ct+tag]` для надсилання каналом.
#[wasm_bindgen]
pub struct WasmSealer {
    inner: StreamSealer,
}

#[wasm_bindgen]
impl WasmSealer {
    pub fn seal(&mut self, plaintext: &[u8]) -> Box<[u8]> {
        self.inner.seal(plaintext).into_boxed_slice()
    }
}

/// Розшифрувальник відео: `[nonce|ct+tag]` (зібраний із чанків) → H.264 access unit (Annex-B).
#[wasm_bindgen]
pub struct WasmOpener {
    inner: StreamOpener,
}

#[wasm_bindgen]
impl WasmOpener {
    pub fn open(&self, wire: &[u8]) -> Result<Box<[u8]>, JsError> {
        self.inner
            .open(wire)
            .map(Vec::into_boxed_slice)
            .map_err(|_| JsError::new("decrypt/auth failed"))
    }
}

/// Збирач відео-чанків: `push(чанк)` → `Some(зашифрований блоб)`, коли всі чанки AU прийшли
/// (далі цей блоб у `WasmOpener::open`). Порядок як у нативному ядрі: зібрати → розшифрувати.
#[wasm_bindgen]
pub struct WasmReassembler {
    inner: Reassembler,
}

#[wasm_bindgen]
impl WasmReassembler {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> WasmReassembler {
        WasmReassembler {
            inner: Reassembler::new(),
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Option<Box<[u8]>> {
        self.inner.push(chunk).map(Vec::into_boxed_slice)
    }
}
