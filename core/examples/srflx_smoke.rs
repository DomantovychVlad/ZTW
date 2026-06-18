//! PoC виявлення srflx: визначає нашу публічну (server-reflexive) адресу через
//! публічний STUN-сервер. Запуск: cargo run -p zortilwatch-core --example srflx_smoke

use std::net::{ToSocketAddrs, UdpSocket};
use zortilwatch_core::net::discover_srflx;

fn main() {
    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind");
    let base = sock.local_addr().unwrap();

    let stun = match "stun.l.google.com:19302"
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
    {
        Some(a) => a,
        None => {
            println!("RESULT=STUN_RESOLVE_FAILED (немає мережі?)");
            return;
        }
    };

    println!("base={base}, stun={stun}");
    match discover_srflx(&sock, stun) {
        Ok(srflx) => println!("RESULT=OK srflx={srflx}"),
        Err(e) => println!("RESULT=FAILED: {e}"),
    }
}
