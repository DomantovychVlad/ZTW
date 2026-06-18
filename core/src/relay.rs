//! Допоміжне для одно-сокетного TURN/ICE.
//!
//! На одному UDP-сокеті співіснують STUN (наш контроль + ICE str0m), DTLS, SRTP і TURN
//! ChannelData. Тут — класифікація вхідних пакетів (RFC 7983) і обгортка/розгортка
//! ChannelData. Клієнт TURN (Allocate + CreatePermission + Send/Data indications) — у
//! модулі `turn` нижче; тунелювання str0m-трафіку крізь ретранслятор перевірено наживо
//! проти coturn (приклад e2e_relay). ChannelBind — оптимізація далі.

/// Тип пакета за першим байтом (RFC 7983, одно-портовий демультиплекс).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// 0..=3 — STUN (наш контроль АБО ICE str0m; розрізняти за transaction id).
    Stun,
    /// 20..=63 — DTLS.
    Dtls,
    /// 64..=79 — TURN ChannelData.
    TurnChannel,
    /// 128..=191 — RTP/RTCP.
    Rtp,
    /// Решта/порожнє.
    Unknown,
}

/// Класифікувати вхідний датаграм за першим байтом.
pub fn classify(packet: &[u8]) -> PacketKind {
    match packet.first().copied() {
        Some(0..=3) => PacketKind::Stun,
        Some(20..=63) => PacketKind::Dtls,
        Some(64..=79) => PacketKind::TurnChannel,
        Some(128..=191) => PacketKind::Rtp,
        _ => PacketKind::Unknown,
    }
}

/// Обгорнути дані у TURN ChannelData: `[channel:2][len:2][data][pad до 4]`.
pub fn wrap_channel_data(channel: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len() + 3);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// Розгорнути TURN ChannelData -> (channel, payload). `None`, якщо формат некоректний
/// (закороткий пакет або номер каналу поза 0x4000..=0x7FFF).
pub fn unwrap_channel_data(packet: &[u8]) -> Option<(u16, &[u8])> {
    if packet.len() < 4 {
        return None;
    }
    let channel = u16::from_be_bytes([packet[0], packet[1]]);
    if !(0x4000..=0x7FFF).contains(&channel) {
        return None;
    }
    let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    packet.get(4..4 + len).map(|d| (channel, d))
}

/// TURN-клієнт (RFC 8656/5766): автентифікований Allocate + CreatePermission + Send/Data
/// indications для тунелювання трафіку крізь ретранслятор. Перевірено наживо проти coturn
/// (e2e_relay: str0m-сесія повністю крізь relay). ChannelBind — оптимізація далі.
pub mod turn {
    use bytecodec::{DecodeExt, EncodeExt};
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Duration;
    use stun_codec::rfc5389::attributes::{ErrorCode, MessageIntegrity, Nonce, Realm, Username};
    use stun_codec::rfc5766::attributes::{
        Data, Lifetime, RequestedTransport, XorPeerAddress, XorRelayAddress,
    };
    use stun_codec::rfc5766::methods::{ALLOCATE, CREATE_PERMISSION, DATA, SEND};
    use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};

    stun_codec::define_attribute_enums!(
        TurnAttr,
        TurnAttrDecoder,
        TurnAttrEncoder,
        [
            Username,
            Realm,
            Nonce,
            MessageIntegrity,
            ErrorCode,
            RequestedTransport,
            XorRelayAddress,
            Lifetime,
            XorPeerAddress,
            Data
        ]
    );

    #[derive(Debug)]
    pub struct TurnError(pub String);

    impl std::fmt::Display for TurnError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "turn error: {}", self.0)
        }
    }

    impl std::error::Error for TurnError {}

    fn err<E: std::fmt::Display>(e: E) -> TurnError {
        TurnError(e.to_string())
    }

    fn txid() -> TransactionId {
        let mut b = [0u8; 12];
        getrandom::getrandom(&mut b).expect("OS CSPRNG failed");
        TransactionId::new(b)
    }

    fn send_recv(
        sock: &UdpSocket,
        server: SocketAddr,
        msg: Message<TurnAttr>,
    ) -> Result<Message<TurnAttr>, TurnError> {
        let bytes = MessageEncoder::new().encode_into_bytes(msg).map_err(err)?;
        sock.send_to(&bytes, server).map_err(err)?;
        let mut buf = [0u8; 1500];
        let (n, _) = sock.recv_from(&mut buf).map_err(err)?;
        MessageDecoder::<TurnAttr>::new()
            .decode_from_bytes(&buf[..n])
            .map_err(err)?
            .map_err(|m| TurnError(format!("broken STUN message: {m:?}")))
    }

    /// Стан TURN-алокації: relayed-адреса + облікові дані (realm/nonce) для подальших
    /// автентифікованих запитів (CreatePermission) без повторного 401.
    pub struct TurnClient {
        pub server: SocketAddr,
        pub relayed: SocketAddr,
        username: String,
        password: String,
        realm: Realm,
        nonce: Nonce,
    }

    impl TurnClient {
        /// TURN Allocate з автентифікацією (RFC 5766): неавтентифікований запит -> 401 з
        /// REALM/NONCE -> повторний запит із MESSAGE-INTEGRITY -> relayed-адреса. Зберігає
        /// realm/nonce для CreatePermission.
        pub fn allocate(
            sock: &UdpSocket,
            server: SocketAddr,
            username: &str,
            password: &str,
        ) -> Result<Self, TurnError> {
            sock.set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(err)?;

            // 1) Неавтентифікований Allocate -> 401 + REALM/NONCE.
            let mut req = Message::new(MessageClass::Request, ALLOCATE, txid());
            req.add_attribute(TurnAttr::RequestedTransport(RequestedTransport::new(17)));
            let resp = send_recv(sock, server, req)?;
            let realm = resp.get_attribute::<Realm>().cloned().ok_or_else(|| {
                let code = resp
                    .get_attribute::<ErrorCode>()
                    .map(|e| e.code())
                    .unwrap_or(0);
                TurnError(format!(
                    "no REALM in challenge (class={:?}, error_code={code})",
                    resp.class()
                ))
            })?;
            let nonce = resp
                .get_attribute::<Nonce>()
                .ok_or_else(|| TurnError("no NONCE in challenge".into()))?
                .clone();

            // 2) Автентифікований Allocate (MESSAGE-INTEGRITY рахується над усім попереднім).
            let uname = Username::new(username.to_string()).map_err(err)?;
            let mut req2 = Message::new(MessageClass::Request, ALLOCATE, txid());
            req2.add_attribute(TurnAttr::RequestedTransport(RequestedTransport::new(17)));
            req2.add_attribute(TurnAttr::Username(uname.clone()));
            req2.add_attribute(TurnAttr::Realm(realm.clone()));
            req2.add_attribute(TurnAttr::Nonce(nonce.clone()));
            let mi = MessageIntegrity::new_long_term_credential(&req2, &uname, &realm, password)
                .map_err(err)?;
            req2.add_attribute(TurnAttr::MessageIntegrity(mi));

            let resp2 = send_recv(sock, server, req2)?;
            if resp2.class() != MessageClass::SuccessResponse {
                let code = resp2
                    .get_attribute::<ErrorCode>()
                    .map(|e| e.code())
                    .unwrap_or(0);
                return Err(TurnError(format!(
                    "Allocate rejected (class={:?}, code={code})",
                    resp2.class()
                )));
            }
            let relayed = resp2
                .get_attribute::<XorRelayAddress>()
                .ok_or_else(|| TurnError("no XOR-RELAYED-ADDRESS".into()))?
                .address();

            Ok(Self {
                server,
                relayed,
                username: username.to_string(),
                password: password.to_string(),
                realm,
                nonce,
            })
        }

        /// CreatePermission для relayed-адреси піра — дозволяє coturn релеїти трафік між
        /// нашою та піровою алокаціями (дозвіл за IP піра; має існувати ДО приходу даних).
        pub fn create_permission(
            &self,
            sock: &UdpSocket,
            peer: SocketAddr,
        ) -> Result<(), TurnError> {
            let uname = Username::new(self.username.clone()).map_err(err)?;
            let mut req = Message::new(MessageClass::Request, CREATE_PERMISSION, txid());
            req.add_attribute(TurnAttr::XorPeerAddress(XorPeerAddress::new(peer)));
            req.add_attribute(TurnAttr::Username(uname.clone()));
            req.add_attribute(TurnAttr::Realm(self.realm.clone()));
            req.add_attribute(TurnAttr::Nonce(self.nonce.clone()));
            let mi = MessageIntegrity::new_long_term_credential(
                &req,
                &uname,
                &self.realm,
                &self.password,
            )
            .map_err(err)?;
            req.add_attribute(TurnAttr::MessageIntegrity(mi));

            let resp = send_recv(sock, self.server, req)?;
            if resp.class() != MessageClass::SuccessResponse {
                let code = resp
                    .get_attribute::<ErrorCode>()
                    .map(|e| e.code())
                    .unwrap_or(0);
                return Err(TurnError(format!(
                    "CreatePermission rejected (class={:?}, code={code})",
                    resp.class()
                )));
            }
            Ok(())
        }
    }

    /// Зворотна сумісність: Allocate -> лише relayed-адреса (без подальших запитів).
    pub fn allocate(
        sock: &UdpSocket,
        server: SocketAddr,
        username: &str,
        password: &str,
    ) -> Result<SocketAddr, TurnError> {
        TurnClient::allocate(sock, server, username, password).map(|c| c.relayed)
    }

    /// Загорнути вихідну датаграму в TURN Send-indication до сервера (для пересилання піру).
    /// Indication НЕ несе MESSAGE-INTEGRITY (RFC 5766 §10.1).
    pub fn encode_send_indication(peer: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, TurnError> {
        let mut ind = Message::<TurnAttr>::new(MessageClass::Indication, SEND, txid());
        ind.add_attribute(TurnAttr::XorPeerAddress(XorPeerAddress::new(peer)));
        ind.add_attribute(TurnAttr::Data(Data::new(payload.to_vec()).map_err(err)?));
        MessageEncoder::new().encode_into_bytes(ind).map_err(err)
    }

    /// Розібрана датаграма, що прийшла ВІД TURN-сервера.
    #[derive(Debug)]
    pub enum TurnInbound {
        /// Data-indication: дані від піра (`peer` — його relayed-адреса).
        Data { peer: SocketAddr, payload: Vec<u8> },
        /// Інше (відповіді на Allocate/CreatePermission/Refresh тощо) — ігноруємо.
        Other,
    }

    /// Розібрати датаграму від TURN-сервера: Data-indication -> (peer, payload), решта -> Other.
    pub fn parse_from_server(buf: &[u8]) -> Result<TurnInbound, TurnError> {
        let msg = MessageDecoder::<TurnAttr>::new()
            .decode_from_bytes(buf)
            .map_err(err)?
            .map_err(|m| TurnError(format!("broken STUN message: {m:?}")))?;
        if msg.method() == DATA && msg.class() == MessageClass::Indication {
            let peer = msg
                .get_attribute::<XorPeerAddress>()
                .ok_or_else(|| TurnError("DATA without XOR-PEER-ADDRESS".into()))?
                .address();
            let payload = msg
                .get_attribute::<Data>()
                .ok_or_else(|| TurnError("DATA without DATA attr".into()))?
                .data()
                .to_vec();
            return Ok(TurnInbound::Data { peer, payload });
        }
        Ok(TurnInbound::Other)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn send_indication_roundtrips_via_decoder() {
            let peer: SocketAddr = "192.168.88.223:49170".parse().unwrap();
            let payload = b"str0m-binding-or-dtls-bytes";
            let bytes = encode_send_indication(peer, payload).unwrap();
            let msg = MessageDecoder::<TurnAttr>::new()
                .decode_from_bytes(&bytes)
                .unwrap()
                .unwrap();
            assert_eq!(msg.method(), SEND);
            assert_eq!(msg.class(), MessageClass::Indication);
            assert_eq!(
                msg.get_attribute::<XorPeerAddress>().unwrap().address(),
                peer
            );
            assert_eq!(msg.get_attribute::<Data>().unwrap().data(), payload);
        }

        #[test]
        fn parse_data_indication_extracts_peer_and_payload() {
            let peer: SocketAddr = "192.168.88.223:49180".parse().unwrap();
            let payload = b"relayed-from-peer";
            let mut ind = Message::<TurnAttr>::new(MessageClass::Indication, DATA, txid());
            ind.add_attribute(TurnAttr::XorPeerAddress(XorPeerAddress::new(peer)));
            ind.add_attribute(TurnAttr::Data(Data::new(payload.to_vec()).unwrap()));
            let bytes = MessageEncoder::new().encode_into_bytes(ind).unwrap();
            match parse_from_server(&bytes).unwrap() {
                TurnInbound::Data {
                    peer: p,
                    payload: d,
                } => {
                    assert_eq!(p, peer);
                    assert_eq!(d, payload);
                }
                other => panic!("expected Data, got {other:?}"),
            }
        }

        #[test]
        fn parse_non_data_is_other() {
            let m =
                Message::<TurnAttr>::new(MessageClass::SuccessResponse, CREATE_PERMISSION, txid());
            let bytes = MessageEncoder::new().encode_into_bytes(m).unwrap();
            assert!(matches!(
                parse_from_server(&bytes).unwrap(),
                TurnInbound::Other
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_by_first_byte() {
        assert_eq!(classify(&[0x00]), PacketKind::Stun);
        assert_eq!(classify(&[0x01]), PacketKind::Stun);
        assert_eq!(classify(&[25]), PacketKind::Dtls);
        assert_eq!(classify(&[0x40]), PacketKind::TurnChannel); // 64
        assert_eq!(classify(&[79]), PacketKind::TurnChannel);
        assert_eq!(classify(&[128]), PacketKind::Rtp);
        assert_eq!(classify(&[200]), PacketKind::Unknown);
        assert_eq!(classify(&[]), PacketKind::Unknown);
    }

    #[test]
    fn channel_data_roundtrip() {
        let data = b"opaque-media-bytes";
        let wrapped = wrap_channel_data(0x4001, data);
        assert_eq!(wrapped.len() % 4, 0); // вирівняно на 4
        assert_eq!(classify(&wrapped), PacketKind::TurnChannel);
        let (ch, payload) = unwrap_channel_data(&wrapped).unwrap();
        assert_eq!(ch, 0x4001);
        assert_eq!(payload, data);
    }

    #[test]
    fn unwrap_rejects_bad_channel_and_short() {
        // Канал поза діапазоном.
        assert!(unwrap_channel_data(&[0x00, 0x01, 0x00, 0x00]).is_none());
        // Закороткий пакет.
        assert!(unwrap_channel_data(&[0x40, 0x01]).is_none());
    }
}
