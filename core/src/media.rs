//! Фреймінг H.264 access units для datachannel.
//!
//! SCTP-повідомлення дата-каналу мають обмежений розмір, а keyframe H.264 буває
//! десятки КБ — тож ріжемо кадр на чанки й збираємо назад. Канал str0m надійний і
//! ВПОРЯДКОВАНИЙ, тож збірка проста (чанки приходять по порядку). Кожен чанк:
//! `[seq:u32][idx:u16][count:u16][payload]` (big-endian). `idx==0` починає новий кадр.

/// Типовий максимум корисного навантаження на чанк (з запасом під ліміт SCTP).
pub const DEFAULT_MAX_PAYLOAD: usize = 16 * 1024;

const HEADER: usize = 8; // seq(4) + idx(2) + count(2)

/// Ріже кадри на впорядковані чанки зі зростаючим seq.
pub struct Chunker {
    seq: u32,
    max_payload: usize,
}

impl Chunker {
    pub fn new(max_payload: usize) -> Self {
        Self {
            seq: 0,
            max_payload: max_payload.max(1),
        }
    }

    /// Чанки одного кадру (мін. один, навіть для порожнього кадру).
    pub fn chunk(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);

        let parts: Vec<&[u8]> = if frame.is_empty() {
            vec![&frame[..0]]
        } else {
            frame.chunks(self.max_payload).collect()
        };
        let count = parts.len() as u16;

        parts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut m = Vec::with_capacity(HEADER + p.len());
                m.extend_from_slice(&seq.to_be_bytes());
                m.extend_from_slice(&(i as u16).to_be_bytes());
                m.extend_from_slice(&count.to_be_bytes());
                m.extend_from_slice(p);
                m
            })
            .collect()
    }
}

/// Збирає чанки назад у кадри (для впорядкованого надійного каналу).
#[derive(Default)]
pub struct Reassembler {
    seq: Option<u32>,
    count: u16,
    got: u16,
    buf: Vec<u8>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Згодувати один чанк; повертає повний кадр на останньому чанку.
    pub fn push(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        if msg.len() < HEADER {
            return None;
        }
        let seq = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]);
        let idx = u16::from_be_bytes([msg[4], msg[5]]);
        let count = u16::from_be_bytes([msg[6], msg[7]]);
        let payload = &msg[HEADER..];

        if idx == 0 {
            // Початок нового кадру — скидаємо стан.
            self.seq = Some(seq);
            self.count = count;
            self.got = 0;
            self.buf.clear();
        }
        if self.seq != Some(seq) {
            return None; // чанк не з поточного кадру (втрата синхронізації)
        }

        self.buf.extend_from_slice(payload);
        self.got += 1;
        if self.got >= self.count {
            self.seq = None;
            return Some(std::mem::take(&mut self.buf));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: &[u8], max_payload: usize) -> Vec<u8> {
        let mut ch = Chunker::new(max_payload);
        let mut re = Reassembler::new();
        let mut out = None;
        for c in ch.chunk(frame) {
            if let Some(f) = re.push(&c) {
                out = Some(f);
            }
        }
        out.expect("frame reassembled")
    }

    #[test]
    fn small_frame_single_chunk() {
        let frame = b"a-tiny-h264-access-unit";
        let mut ch = Chunker::new(DEFAULT_MAX_PAYLOAD);
        assert_eq!(ch.chunk(frame).len(), 1);
        assert_eq!(roundtrip(frame, DEFAULT_MAX_PAYLOAD), frame);
    }

    #[test]
    fn large_frame_chunked_and_reassembled() {
        let frame: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let mut ch = Chunker::new(16 * 1024);
        let chunks = ch.chunk(&frame);
        assert!(chunks.len() >= 5, "expected several chunks");
        assert_eq!(roundtrip(&frame, 16 * 1024), frame);
    }

    #[test]
    fn empty_frame_roundtrips() {
        assert_eq!(roundtrip(&[], 1024), Vec::<u8>::new());
    }

    #[test]
    fn two_frames_sequential() {
        let mut ch = Chunker::new(8);
        let mut re = Reassembler::new();
        let f1: Vec<u8> = (0..20u8).collect();
        let f2: Vec<u8> = (100..130u8).collect();

        let mut got = Vec::new();
        for c in ch.chunk(&f1).into_iter().chain(ch.chunk(&f2)) {
            if let Some(f) = re.push(&c) {
                got.push(f);
            }
        }
        assert_eq!(got, vec![f1, f2]);
    }

    #[test]
    fn seq_increments_across_frames() {
        let mut ch = Chunker::new(1024);
        let a = ch.chunk(b"x");
        let b = ch.chunk(b"y");
        assert_eq!(&a[0][0..4], &0u32.to_be_bytes());
        assert_eq!(&b[0][0..4], &1u32.to_be_bytes());
    }
}
