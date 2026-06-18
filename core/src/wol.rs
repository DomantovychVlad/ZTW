//! Wake-on-LAN (PRD 5.9): побудова й надсилання «магічного пакета».
//!
//! Магічний пакет = 6 байтів 0xFF + 16 повторів MAC-адреси цілі (102 байти). Це
//! локальний широкомовний UDP — діє лише в межах мережі відправника, тож шле його
//! ПОМІЧНИК (онлайн-пристрій у тій самій мережі, що й сплячий ПК), не сам пульт.

use std::net::UdpSocket;

/// Розпарсити MAC у 6 байтів. Приймає "AA:BB:CC:DD:EE:FF", "AA-BB-..." або "aabbcc...".
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

/// Канонічний рядок MAC (верхній регістр, двокрапки) — для збереження/показу.
pub fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// 102-байтовий магічний пакет для заданого MAC.
pub fn magic_packet(mac: [u8; 6]) -> [u8; 102] {
    let mut p = [0xFFu8; 102];
    for chunk in p[6..].chunks_mut(6) {
        chunk.copy_from_slice(&mac);
    }
    p
}

/// Надіслати магічний пакет широкомовно (порти 9 і 7 — обидва стандартні для WoL).
/// Виконується на ПОМІЧНИКУ. `Ok(())`, якщо пакет вилетів у мережу.
pub fn send_wol(mac: [u8; 6]) -> std::io::Result<()> {
    let packet = magic_packet(mac);
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    sock.send_to(&packet, "255.255.255.255:9")?;
    let _ = sock.send_to(&packet, "255.255.255.255:7");
    Ok(())
}

/// Зручний варіант із рядка MAC. `false`, якщо MAC некоректний або сокет не вдався.
pub fn send_wol_str(mac: &str) -> bool {
    match parse_mac(mac) {
        Some(m) => send_wol(m).is_ok(),
        None => false,
    }
}

/// MAC адаптера, через який пристрій під'єднаний (для звіту серверу — щоб його можна
/// було розбудити). Перший «робочий» фізичний адаптер (Ethernet/Wi-Fi, up, не loopback).
#[cfg(windows)]
pub fn local_mac() -> Option<String> {
    win::local_mac()
}

#[cfg(windows)]
mod win {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    const IF_TYPE_ETHERNET: u32 = 6;
    const IF_TYPE_WIFI: u32 = 71;
    const OPER_STATUS_UP: i32 = 1;

    pub fn local_mac() -> Option<String> {
        unsafe {
            // Двофазний виклик: дізнатися розмір, тоді заповнити.
            let mut size = 0u32;
            let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
            let _ = GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, None, &mut size);
            if size == 0 {
                return None;
            }
            let mut buf = vec![0u8; size as usize];
            let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            if GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(head), &mut size) != 0 {
                return None;
            }
            let mut cur = head;
            while !cur.is_null() {
                let a = &*cur;
                let kind = a.IfType;
                let up = a.OperStatus.0 == OPER_STATUS_UP;
                let len = a.PhysicalAddressLength as usize;
                if (kind == IF_TYPE_ETHERNET || kind == IF_TYPE_WIFI) && up && len == 6 {
                    let m = &a.PhysicalAddress;
                    if m[..6].iter().any(|&b| b != 0) {
                        return Some(super::format_mac([m[0], m[1], m[2], m[3], m[4], m[5]]));
                    }
                }
                cur = a.Next;
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_accepts_common_forms() {
        let want = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(parse_mac("AA:BB:CC:DD:EE:FF"), Some(want));
        assert_eq!(parse_mac("aa-bb-cc-dd-ee-ff"), Some(want));
        assert_eq!(parse_mac("AABBCCDDEEFF"), Some(want));
        assert_eq!(parse_mac("AA BB CC DD EE FF"), Some(want));
        assert_eq!(parse_mac("not-a-mac"), None);
        assert_eq!(parse_mac("AA:BB:CC"), None); // закоротко
    }

    #[test]
    fn format_mac_is_canonical() {
        assert_eq!(
            format_mac([0x01, 0x23, 0x45, 0x67, 0x89, 0xab]),
            "01:23:45:67:89:AB"
        );
        // round-trip
        let mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11];
        assert_eq!(parse_mac(&format_mac(mac)), Some(mac));
    }

    #[test]
    fn magic_packet_shape() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let p = magic_packet(mac);
        assert_eq!(&p[..6], &[0xFF; 6]); // префікс
        for i in 0..16 {
            assert_eq!(&p[6 + i * 6..6 + i * 6 + 6], &mac); // 16 повторів MAC
        }
    }

    #[test]
    fn send_wol_str_rejects_bad_mac() {
        assert!(!send_wol_str("nope"));
    }
}
