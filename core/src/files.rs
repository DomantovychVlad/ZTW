//! Передача файлів (PRD 5.7): фреймінг бінарних чанків усередині зашифрованого
//! каналу сесії та список каталогів керованого.
//!
//! Кадр файла (обидва напрями, ВСЕРЕДИНІ sealed-повідомлення):
//! `[0xF7][id: u32 BE][offset: u64 BE][дані…]` — магічний байт відрізняє його від
//! JSON (`{`) та H.264 Annex-B (`\0\0…`). Канал надійний і впорядкований (SCTP),
//! тож offset монотонний; resume = старт з offset, який повідомляє інша сторона.

use serde_json::{json, Value};

/// Перший байт бінарного файлового кадру.
pub const FILE_FRAME_MAGIC: u8 = 0xF7;
/// Розмір порції файла на один кадр (вписується в чанкінг каналу без фрагментації шифру).
pub const FILE_CHUNK: usize = 32 * 1024;

/// Зібрати кадр файла.
pub fn encode_file_frame(id: u32, offset: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + 8 + data.len());
    out.push(FILE_FRAME_MAGIC);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Розібрати кадр файла; `None`, якщо це не він.
pub fn parse_file_frame(buf: &[u8]) -> Option<(u32, u64, &[u8])> {
    if buf.len() < 13 || buf[0] != FILE_FRAME_MAGIC {
        return None;
    }
    let id = u32::from_be_bytes(buf[1..5].try_into().ok()?);
    let offset = u64::from_be_bytes(buf[5..13].try_into().ok()?);
    Some((id, offset, &buf[13..]))
}

/// Список каталогу для пульта. Порожній шлях — корені (диски на Windows).
/// Повертає JSON: `{"path", "entries":[{"name","dir","size"}], "err"}`.
pub fn list_dir(path: &str) -> Value {
    if path.is_empty() {
        // Диски: A:..Z: (дешева перевірка існування кореня).
        let entries: Vec<Value> = (b'A'..=b'Z')
            .filter_map(|c| {
                let root = format!("{}:\\", c as char);
                std::path::Path::new(&root)
                    .exists()
                    .then(|| json!({ "name": root, "dir": true, "size": 0 }))
            })
            .collect();
        return json!({ "path": "", "entries": entries, "err": null });
    }
    match std::fs::read_dir(path) {
        Ok(rd) => {
            let mut entries: Vec<Value> = rd
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let meta = e.metadata().ok()?;
                    Some(json!({
                        "name": e.file_name().to_string_lossy(),
                        "dir": meta.is_dir(),
                        "size": meta.len(),
                    }))
                })
                .collect();
            entries.sort_by(|a, b| {
                let (ad, bd) = (a["dir"].as_bool().unwrap(), b["dir"].as_bool().unwrap());
                bd.cmp(&ad)
                    .then(a["name"].as_str().cmp(&b["name"].as_str()))
            });
            json!({ "path": path, "entries": entries, "err": null })
        }
        Err(e) => json!({ "path": path, "entries": [], "err": e.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_frame_roundtrip() {
        let f = encode_file_frame(7, 1_000_000, b"hello");
        let (id, off, data) = parse_file_frame(&f).expect("parse");
        assert_eq!((id, off, data), (7, 1_000_000, b"hello".as_slice()));
        assert!(parse_file_frame(b"\x00\x00\x01rest").is_none()); // H.264 — не файл
        assert!(parse_file_frame(b"{\"j\":1}").is_none()); // JSON — не файл
    }

    #[test]
    fn list_dir_reads_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let v = list_dir(dir.path().to_str().unwrap());
        let names: Vec<&str> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["sub", "a.txt"]); // теки першими
        assert!(v["err"].is_null());
    }

    #[test]
    fn list_dir_error_is_reported() {
        let v = list_dir("Z:\\definitely\\not\\here\\zw");
        assert!(v["err"].is_string());
        assert_eq!(v["entries"].as_array().unwrap().len(), 0);
    }
}
