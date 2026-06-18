//! Мережеве ядро на str0m (WebRTC).
//!
//! str0m — sans-IO: він НЕ має власного годинника й НЕ робить мережевих операцій сам;
//! застосунок керує циклом (`poll_output`/`handle_input`) і шле байти. str0m також
//! НЕ має вбудованого TURN-клієнта — релей-кандидати додаємо окремо (Етап далі).

use std::sync::Once;
use std::time::Instant;
use str0m::{Rtc, RtcConfig};

static CRYPTO_INIT: Once = Once::new();

fn ensure_crypto() {
    CRYPTO_INIT.call_once(|| {
        str0m::crypto::from_feature_flags().install_process_default();
    });
}

/// Створити новий `Rtc` із зовнішнім годинником `now`.
pub fn new_rtc(now: Instant) -> Rtc {
    ensure_crypto();
    RtcConfig::new().build(now)
}

/// Виявити server-reflexive (srflx) адресу на сокеті через STUN-сервер. Сокет — той
/// самий, що його драйвитиме str0m. Далі: add_local_candidate(Candidate::server_reflexive).
pub fn discover_srflx(
    sock: &std::net::UdpSocket,
    stun_server: std::net::SocketAddr,
) -> Result<std::net::SocketAddr, String> {
    stunclient::StunClient::new(stun_server)
        .query_external_address(sock)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Duration;
    use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
    use str0m::channel::ChannelId;
    use str0m::net::{Protocol, Receive};
    use str0m::{Candidate, Event, Input, Output, Rtc};

    struct Peer {
        rtc: Rtc,
        sock: UdpSocket,
        addr: SocketAddr,
        chan: Option<ChannelId>,
        received: Vec<String>,
    }

    impl Peer {
        fn new(now: Instant) -> Self {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_nonblocking(true).unwrap();
            let addr = sock.local_addr().unwrap();
            let mut rtc = new_rtc(now);
            rtc.add_local_candidate(Candidate::host(addr, "udp").unwrap());
            Peer {
                rtc,
                sock,
                addr,
                chan: None,
                received: Vec::new(),
            }
        }

        /// Вичерпати poll_output: відіслати Transmit, зафіксувати відкриття каналу й дані.
        /// Повертає момент наступного таймауту.
        fn drain(&mut self) -> Instant {
            loop {
                match self.rtc.poll_output().unwrap() {
                    Output::Timeout(t) => return t,
                    Output::Transmit(t) => {
                        let _ = self.sock.send_to(&t.contents, t.destination);
                    }
                    Output::Event(Event::ChannelOpen(id, _label)) => {
                        self.chan = Some(id);
                    }
                    Output::Event(Event::ChannelData(d)) => {
                        self.received
                            .push(String::from_utf8_lossy(&d.data).to_string());
                    }
                    Output::Event(_) => {}
                }
            }
        }

        /// Зчитати всі наявні UDP-датаграми в rtc.
        fn recv(&mut self, now: Instant) {
            let mut buf = [0u8; 2048];
            loop {
                match self.sock.recv_from(&mut buf) {
                    Ok((n, source)) => {
                        let contents = buf[..n].try_into().unwrap();
                        self.rtc
                            .handle_input(Input::Receive(
                                now,
                                Receive {
                                    proto: Protocol::Udp,
                                    source,
                                    destination: self.addr,
                                    contents,
                                },
                            ))
                            .unwrap();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("recv_from: {e:?}"),
                }
            }
        }
    }

    #[test]
    fn loopback_datachannel_delivers_message() {
        let mut now = Instant::now();
        let mut a = Peer::new(now);
        let mut b = Peer::new(now);

        a.rtc
            .add_remote_candidate(Candidate::host(b.addr, "udp").unwrap());
        b.rtc
            .add_remote_candidate(Candidate::host(a.addr, "udp").unwrap());

        // A пропонує дата-канал; B відповідає. Дренуємо після кожної мутації (інваріант str0m).
        a.drain();
        b.drain();
        let mut api = a.rtc.sdp_api();
        let _staged: ChannelId = api.add_channel("data".to_string());
        let (offer, pending): (SdpOffer, SdpPendingOffer) = api.apply().expect("offer has changes");
        a.drain();
        let answer: SdpAnswer = b.rtc.sdp_api().accept_offer(offer).expect("accept offer");
        b.drain();
        a.rtc
            .sdp_api()
            .accept_answer(pending, answer)
            .expect("accept answer");
        a.drain();

        let deadline = Instant::now() + Duration::from_secs(15);
        let mut sent = false;
        while b.received.is_empty() {
            assert!(
                Instant::now() < deadline,
                "loopback handshake/data timed out"
            );

            let ta = a.drain();
            let tb = b.drain();

            if !sent {
                if let Some(cid) = a.chan {
                    if let Some(mut ch) = a.rtc.channel(cid) {
                        ch.write(false, b"hello-from-A").unwrap();
                        sent = true;
                    }
                }
            }

            a.recv(now);
            b.recv(now);

            // Зсуваємо спільний годинник до найближчого таймауту (без busy-spin).
            now = ta.min(tb).max(now + Duration::from_millis(1));
            a.rtc.handle_input(Input::Timeout(now)).unwrap();
            b.rtc.handle_input(Input::Timeout(now)).unwrap();
        }

        assert_eq!(b.received[0], "hello-from-A");
    }

    // Наскрізне: захищена сесія B1 (PAKE + прив'язка) поверх СПРАВЖНЬОГО str0m-каналу.
    #[test]
    fn secure_session_over_datachannel() {
        use crate::session::{Handshake, SessionMessage};

        const PW: &[u8] = b"shared-one-time-pw";

        fn write_msg(rtc: &mut Rtc, cid: ChannelId, msg: &SessionMessage) {
            let bytes = serde_json::to_vec(msg).unwrap();
            if let Some(mut ch) = rtc.channel(cid) {
                let _ = ch.write(false, &bytes);
            }
        }

        let mut now = Instant::now();
        let mut a = Peer::new(now);
        let mut b = Peer::new(now);
        a.rtc
            .add_remote_candidate(Candidate::host(b.addr, "udp").unwrap());
        b.rtc
            .add_remote_candidate(Candidate::host(a.addr, "udp").unwrap());

        a.drain();
        b.drain();
        let mut api = a.rtc.sdp_api();
        let _staged: ChannelId = api.add_channel("session".to_string());
        let (offer, pending): (SdpOffer, SdpPendingOffer) = api.apply().expect("offer");
        a.drain();
        let answer: SdpAnswer = b.rtc.sdp_api().accept_offer(offer).expect("answer");
        b.drain();
        a.rtc
            .sdp_api()
            .accept_answer(pending, answer)
            .expect("accept");
        a.drain();

        let mut a_hs: Option<Handshake> = None;
        let mut b_hs: Option<Handshake> = None;

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let a_ok = a_hs.as_ref().is_some_and(|h| h.is_confirmed());
            let b_ok = b_hs.as_ref().is_some_and(|h| h.is_confirmed());
            if a_ok && b_ok {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "secure session over channel timed out"
            );

            let ta = a.drain();
            let tb = b.drain();

            // Старт рукостискання, щойно канал відкрився (обидва шлють свій Pake).
            if a_hs.is_none() {
                if let Some(cid) = a.chan {
                    let (hs, msg) = Handshake::start(PW, "A".into(), "B".into());
                    a_hs = Some(hs);
                    write_msg(&mut a.rtc, cid, &msg);
                }
            }
            if b_hs.is_none() {
                if let Some(cid) = b.chan {
                    let (hs, msg) = Handshake::start(PW, "B".into(), "A".into());
                    b_hs = Some(hs);
                    write_msg(&mut b.rtc, cid, &msg);
                }
            }

            // Вхідні повідомлення -> у рукостискання; відповіді -> назад у канал.
            let a_msgs: Vec<String> = a.received.drain(..).collect();
            for s in a_msgs {
                if let (Some(hs), Some(cid)) = (a_hs.as_mut(), a.chan) {
                    if let Ok(msg) = serde_json::from_str::<SessionMessage>(&s) {
                        if let Some(resp) = hs.on_message(msg) {
                            write_msg(&mut a.rtc, cid, &resp);
                        }
                    }
                }
            }
            let b_msgs: Vec<String> = b.received.drain(..).collect();
            for s in b_msgs {
                if let (Some(hs), Some(cid)) = (b_hs.as_mut(), b.chan) {
                    if let Ok(msg) = serde_json::from_str::<SessionMessage>(&s) {
                        if let Some(resp) = hs.on_message(msg) {
                            write_msg(&mut b.rtc, cid, &resp);
                        }
                    }
                }
            }

            a.recv(now);
            b.recv(now);
            now = ta.min(tb).max(now + Duration::from_millis(1));
            a.rtc.handle_input(Input::Timeout(now)).unwrap();
            b.rtc.handle_input(Input::Timeout(now)).unwrap();
        }

        let a_hs = a_hs.unwrap();
        let b_hs = b_hs.unwrap();
        assert!(a_hs.is_confirmed() && b_hs.is_confirmed());
        assert_eq!(a_hs.confirmed_key(), b_hs.confirmed_key());
    }
}
