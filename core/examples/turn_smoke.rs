//! PoC TURN Allocate проти справжнього coturn. Бере адресу/обліковки з env (типово
//! локальний coturn зі статичним user). Запуск:
//!   TURN_SERVER=127.0.0.1:3478 TURN_USER=test TURN_PASS=test123 \
//!     cargo run -p zortilwatch-core --example turn_smoke

use std::net::{ToSocketAddrs, UdpSocket};
use zortilwatch_core::relay::turn;

fn main() {
    let server = std::env::var("TURN_SERVER").unwrap_or_else(|_| "127.0.0.1:3478".into());
    let user = std::env::var("TURN_USER").unwrap_or_else(|_| "test".into());
    let pass = std::env::var("TURN_PASS").unwrap_or_else(|_| "test123".into());

    let server_addr = match server.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(a) => a,
        None => {
            println!("RESULT=BAD_SERVER {server}");
            return;
        }
    };
    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind");
    println!("TURN Allocate на {server_addr} як '{user}'...");

    match turn::allocate(&sock, server_addr, &user, &pass) {
        Ok(relayed) => println!("RESULT=OK relayed transport address = {relayed}"),
        Err(e) => println!("RESULT=FAIL {e}"),
    }
}
