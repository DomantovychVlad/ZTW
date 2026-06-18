//! Ідентичність пристрою: стабільний публічний ID + client_secret + псевдонім,
//! що зберігаються між запусками (рішення з Етапу 1 — ID видає сервер, ядро персистить).

use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Стабільний 9-значний публічний ID (видається сервером при реєстрації).
    pub public_id: String,
    /// Секрет автентифікації сокета (зберігається локально, сервер тримає лише хеш).
    pub client_secret: String,
    /// Зрозумілий псевдонім (наприклад, «Домашній ПК»).
    #[serde(default)]
    pub alias: Option<String>,
}

impl DeviceIdentity {
    pub fn new(public_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            public_id: public_id.into(),
            client_secret: client_secret.into(),
            alias: None,
        }
    }

    /// Завантажити збережену ідентичність; `None`, якщо файлу ще немає (перший запуск).
    pub fn load(path: &Path) -> io::Result<Option<Self>> {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Зберегти ідентичність (персистентність між запусками).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let s = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("identity.json");
        let mut id = DeviceIdentity::new("123456789", "deadbeef");
        id.alias = Some("Домашній ПК".into());
        id.save(&path).unwrap();
        assert_eq!(DeviceIdentity::load(&path).unwrap(), Some(id));
    }

    #[test]
    fn load_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.json");
        assert_eq!(DeviceIdentity::load(&path).unwrap(), None);
    }

    #[test]
    fn alias_defaults_to_none() {
        assert_eq!(DeviceIdentity::new("900000001", "secret").alias, None);
    }
}
