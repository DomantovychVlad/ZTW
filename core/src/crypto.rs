//! Наскрізне крипто сесії (рішення B1).
//!
//! Пароль підключення (одноразовий чи постійний) працює як автентифікатор PAKE:
//! навіть зламаний сигналінг-сервер не може прочитати чи підмінити сесію. Похідний
//! сесійний ключ прив'язується до DTLS-відбитків, щоб закрити MITM на сервері.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

const APP_ID: &[u8] = b"zortilwatch-session-v1";

/// Мітки напрямків шифр-потоків (різні ключі через HKDF-`label`; лічильникові nonce не
/// перетинаються між напрямами). СПІЛЬНІ для нативного ядра й wasm-пульта — мусять збігатися
/// побайтно, інакше сторони виведуть різні ключі й не розшифрують одна одну.
pub const STREAM_LABEL_MEDIA_H2C: &[u8] = b"zortilwatch media h2c v1"; // відео керований -> пульт
pub const STREAM_LABEL_INPUT_C2H: &[u8] = b"zortilwatch ctrl c2h v1"; // ввід пульт -> керований

#[derive(Debug)]
pub enum CryptoError {
    Handshake,
    Kdf,
    Aead,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CryptoError::Handshake => "PAKE handshake failed",
            CryptoError::Kdf => "key derivation failed",
            CryptoError::Aead => "media AEAD open failed",
        })
    }
}

impl std::error::Error for CryptoError {}

pub type PakeState = Spake2<Ed25519Group>;

/// Почати симетричний PAKE на спільному паролі (OsRng). Повертає стан і вихідне
/// повідомлення для піра. Потребує getrandom (фіча `native`); для wasm — [`pake_start_with_rng`].
#[cfg(feature = "native")]
pub fn pake_start(password: &[u8]) -> (PakeState, Vec<u8>) {
    Spake2::<Ed25519Group>::start_symmetric(&Password::new(password), &Identity::new(APP_ID))
}

/// Те саме, але з ЯВНИМ CSPRNG — для wasm (браузерний ChaCha20Rng, засіяний із
/// `crypto.getRandomValues`), без залежності від getrandom/OsRng.
pub fn pake_start_with_rng(
    password: &[u8],
    rng: impl rand_core::CryptoRng + rand_core::RngCore,
) -> (PakeState, Vec<u8>) {
    Spake2::<Ed25519Group>::start_symmetric_with_rng(
        &Password::new(password),
        &Identity::new(APP_ID),
        rng,
    )
}

/// Завершити PAKE вхідним повідомленням піра -> 32-байтний сесійний ключ.
///
/// УВАГА: при різних паролях finish НЕ повертає помилку — він дає ІНШИЙ ключ на
/// кожній стороні. Розбіжність ловить наступний крок (`session_binding` / підтвердження).
pub fn pake_finish(state: PakeState, inbound: &[u8]) -> Result<[u8; 32], CryptoError> {
    let shared = state.finish(inbound).map_err(|_| CryptoError::Handshake)?;
    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut key = [0u8; 32];
    hk.expand(b"zortilwatch session key v1", &mut key)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

/// Тег прив'язки сесії до DTLS-відбитків обох пірів. Канонічний порядок відбитків
/// гарантує, що обидві сторони рахують однаковий тег незалежно від ролі; якщо сервер
/// підмінив відбиток — теги розійдуться й сесію треба розірвати.
pub fn session_binding(session_key: &[u8; 32], fp_a: &str, fp_b: &str) -> [u8; 32] {
    let (lo, hi) = if fp_a <= fp_b {
        (fp_a, fp_b)
    } else {
        (fp_b, fp_a)
    };
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(session_key).expect("HMAC accepts any key length");
    mac.update(b"dtls-binding-v1\0");
    mac.update(lo.as_bytes());
    mac.update(b"\0");
    mac.update(hi.as_bytes());
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Похідний ключ напрямкового шифр-потоку сесії. Різні `label` (відео h→c, ввід c→h,
/// курсор, буфер обміну…) дають РІЗНІ ключі — тож лічильникові nonce ніколи не
/// повторюються між потоками, навіть якщо обидва починають з 0.
pub fn derive_stream_key(session_key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, session_key);
    let mut k = [0u8; 32];
    hk.expand(label, &mut k).expect("hkdf stream expand");
    k
}

/// Шифрувальник напрямкового потоку (бік відправника). AEAD ChaCha20-Poly1305 на похідному
/// від сесійного ключі — E2E-шар ПОВЕРХ DTLS: relay, що термінує DTLS, без PAKE-ключа
/// вмісту не прочитає. Nonce — лічильник; кожен напрям має власний `label` (свій ключ).
pub struct StreamSealer {
    aead: ChaCha20Poly1305,
    counter: u64,
}

impl StreamSealer {
    pub fn new(session_key: &[u8; 32], label: &[u8]) -> Self {
        let k = derive_stream_key(session_key, label);
        Self {
            aead: <ChaCha20Poly1305 as KeyInit>::new_from_slice(&k).expect("32-byte key"),
            counter: 0,
        }
    }

    /// Запечатати повідомлення -> `[nonce:12][ciphertext+tag]`.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        let ct = self
            .aead
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .expect("aead seal");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }
}

/// Розшифрувальник напрямкового потоку (бік отримувача). `label` має збігатися з відправником.
pub struct StreamOpener {
    aead: ChaCha20Poly1305,
}

impl StreamOpener {
    pub fn new(session_key: &[u8; 32], label: &[u8]) -> Self {
        let k = derive_stream_key(session_key, label);
        Self {
            aead: <ChaCha20Poly1305 as KeyInit>::new_from_slice(&k).expect("32-byte key"),
        }
    }

    /// Відкрити `[nonce:12][ciphertext+tag]` -> повідомлення. Помилка, якщо ключ/тег не збігся.
    pub fn open(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if msg.len() < 12 {
            return Err(CryptoError::Aead);
        }
        let (nonce, ct) = msg.split_at(12);
        self.aead
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| CryptoError::Aead)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_pake(pw_a: &[u8], pw_b: &[u8]) -> ([u8; 32], [u8; 32]) {
        let (sa, ma) = pake_start(pw_a);
        let (sb, mb) = pake_start(pw_b);
        let ka = pake_finish(sa, &mb).unwrap();
        let kb = pake_finish(sb, &ma).unwrap();
        (ka, kb)
    }

    #[test]
    fn same_password_yields_same_key() {
        let (ka, kb) = run_pake(b"hunter2", b"hunter2");
        assert_eq!(ka, kb);
    }

    #[test]
    fn different_password_yields_different_key() {
        let (ka, kb) = run_pake(b"hunter2", b"wrong-pass");
        assert_ne!(ka, kb);
    }

    #[test]
    fn binding_matches_regardless_of_argument_order() {
        let (ka, kb) = run_pake(b"pw", b"pw");
        let a = session_binding(&ka, "AA:BB", "CC:DD");
        let b = session_binding(&kb, "CC:DD", "AA:BB");
        assert_eq!(a, b);
    }

    #[test]
    fn binding_changes_if_a_fingerprint_is_swapped() {
        let (ka, _) = run_pake(b"pw", b"pw");
        let honest = session_binding(&ka, "AA:BB", "CC:DD");
        let mitm = session_binding(&ka, "AA:BB", "EVIL:FP");
        assert_ne!(honest, mitm);
    }

    const SLABEL: &[u8] = b"test stream v1";

    #[test]
    fn stream_seal_open_roundtrip() {
        let (ka, kb) = run_pake(b"pw", b"pw"); // ka == kb -> однаковий потоковий ключ
        let mut sealer = StreamSealer::new(&ka, SLABEL);
        let opener = StreamOpener::new(&kb, SLABEL);
        for plain in [&b"frame-one"[..], b"another-h264-access-unit", b""] {
            let sealed = sealer.seal(plain);
            assert_ne!(&sealed[12..], plain); // справді зашифровано (не plaintext)
            assert_eq!(opener.open(&sealed).unwrap(), plain);
        }
    }

    #[test]
    fn stream_open_fails_with_wrong_key() {
        let (ka, _) = run_pake(b"pw", b"pw");
        let (kx, _) = run_pake(b"other", b"other");
        let sealed = StreamSealer::new(&ka, SLABEL).seal(b"secret-frame");
        assert!(StreamOpener::new(&kx, SLABEL).open(&sealed).is_err());
    }

    #[test]
    fn stream_open_fails_on_tamper() {
        let (ka, _) = run_pake(b"pw", b"pw");
        let mut sealed = StreamSealer::new(&ka, SLABEL).seal(b"secret-frame");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01; // псуємо тег автентифікації
        assert!(StreamOpener::new(&ka, SLABEL).open(&sealed).is_err());
    }

    #[test]
    fn stream_key_is_domain_separated_from_session_key() {
        let (ka, _) = run_pake(b"pw", b"pw");
        assert_ne!(derive_stream_key(&ka, SLABEL), ka);
    }

    #[test]
    fn different_labels_give_different_keys() {
        let (ka, _) = run_pake(b"pw", b"pw");
        assert_ne!(
            derive_stream_key(&ka, b"h2c"),
            derive_stream_key(&ka, b"c2h")
        );
        // отримувач іншого напряму не відкриє
        let sealed = StreamSealer::new(&ka, b"h2c").seal(b"x");
        assert!(StreamOpener::new(&ka, b"c2h").open(&sealed).is_err());
    }
}
