//! Capsule Protocol framing (RFC 9297 §3) for DATAGRAM capsules (§3.5).

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{MAX_UDP_PAYLOAD, MasqueError};

/// Capsule type of a DATAGRAM capsule.
const DATAGRAM: u64 = 0x00;

/// Largest DATAGRAM capsule value buffered: a Context ID and the largest UDP payload.
const MAX_DATAGRAM: usize = 8 + MAX_UDP_PAYLOAD;

/// Appends a DATAGRAM capsule carrying `payload` under Context ID 0.
pub(super) fn encode_datagram(payload: &[u8], buf: &mut BytesMut) {
    put_varint(buf, DATAGRAM);
    put_varint(buf, payload.len() as u64 + 1);
    buf.put_u8(0);
    buf.put_slice(payload);
}

/// Writes a QUIC variable-length integer (RFC 9000 §16); `value` must be below 2^62.
fn put_varint(buf: &mut BytesMut, value: u64) {
    debug_assert!(value < 1 << 62);
    let (tag, len) = match value {
        0..0x40 => (0, 1),
        0x40..0x4000 => (0x4000, 2),
        0x4000..0x4000_0000 => (0x8000_0000, 4),
        _ => (0xC000_0000_0000_0000, 8),
    };
    buf.put_uint(tag | value, len);
}

/// Reads a QUIC variable-length integer from the front of `buf`, returning it and its encoded
/// length, or `None` if `buf` ends first.
pub(super) fn varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1 << (first >> 6);
    let bytes = buf.get(1..len)?;
    let value = bytes.iter().fold(u64::from(first & 0x3F), |value, &b| {
        value << 8 | u64::from(b)
    });
    Some((value, len))
}

/// Streaming capsule decoder yielding DATAGRAM capsule values.
///
/// Capsules of other types, and DATAGRAM capsules too large to buffer whose Context ID is not
/// 0, are skipped as their bytes arrive (RFC 9297 §3.2, §3.5).
#[derive(Debug, Default)]
pub(super) struct Decoder {
    skip: u64,
}

impl Decoder {
    /// Takes the next DATAGRAM capsule value from `buf`; `None` means more bytes are needed.
    ///
    /// A Context ID 0 capsule too large to carry a UDP payload is malformed (RFC 9298 §5).
    pub(super) fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Bytes>, MasqueError> {
        loop {
            if self.skip > 0 {
                let n = usize::try_from(self.skip).map_or(buf.len(), |skip| skip.min(buf.len()));
                buf.advance(n);
                self.skip -= n as u64;
                if self.skip > 0 {
                    return Ok(None);
                }
            }
            let Some((kind, kind_len)) = varint(buf) else {
                return Ok(None);
            };
            let Some((len, len_len)) = varint(&buf[kind_len..]) else {
                return Ok(None);
            };
            let header = kind_len + len_len;
            if kind == DATAGRAM {
                match usize::try_from(len) {
                    Ok(len) if len <= MAX_DATAGRAM => {
                        if buf.len() < header + len {
                            buf.reserve(header + len - buf.len());
                            return Ok(None);
                        }
                        buf.advance(header);
                        return Ok(Some(buf.split_to(len).freeze()));
                    }
                    // Longer than any Context ID plus UDP payload, so it fits the Context ID.
                    _ => match varint(&buf[header..]) {
                        None => return Ok(None),
                        Some((0, _)) => return Err(MasqueError::Malformed),
                        Some(_) => {}
                    },
                }
            }
            buf.advance(header);
            self.skip = len;
        }
    }

    /// Whether the stream stopped inside a capsule, which is malformed at its end
    /// (RFC 9297 §3.3).
    pub(super) fn is_partial(&self, buf: &BytesMut) -> bool {
        self.skip > 0 || !buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for (value, len) in [
            (0, 1),
            (63, 1),
            (64, 2),
            (16383, 2),
            (16384, 4),
            (1 << 30, 8),
        ] {
            let mut buf = BytesMut::new();
            put_varint(&mut buf, value);
            assert_eq!(buf.len(), len, "{value}");
            assert_eq!(varint(&buf), Some((value, len)));
            assert_eq!(varint(&buf[..len - 1]), None, "{value} truncated");
        }
        // Non-minimal encodings are valid (RFC 9000 §16).
        assert_eq!(varint(&[0x40, 0x05]), Some((5, 2)));
    }

    #[test]
    fn decodes_streamed_capsules() {
        fn feed(decoder: &mut Decoder, stream: &[u8], chunk: usize) -> Vec<Bytes> {
            let mut buf = BytesMut::new();
            let mut values = Vec::new();
            for bytes in stream.chunks(chunk) {
                buf.extend_from_slice(bytes);
                while let Some(value) = decoder.decode(&mut buf).unwrap() {
                    values.push(value);
                }
            }
            assert!(!decoder.is_partial(&buf));
            values
        }

        // Byte by byte, skipping an unknown (GREASE) capsule.
        let mut stream = BytesMut::new();
        encode_datagram(b"one", &mut stream);
        stream.put_slice(&[0x17, 4]);
        stream.put_slice(b"skip");
        encode_datagram(b"two", &mut stream);
        let values = feed(&mut Decoder::default(), &stream, 1);
        assert_eq!(values, [&b"\0one"[..], &b"\0two"[..]]);

        // The largest UDP payloads are kept, even behind an 8-byte Context ID 0, while an
        // unknown Context ID too large to buffer is skipped.
        let mut stream = BytesMut::new();
        encode_datagram(&[7; 65527], &mut stream);
        stream.put_slice(&[0, 0x80, 0, 0xFF, 0xFF]);
        stream.put_slice(&[0xC0, 0, 0, 0, 0, 0, 0, 0]);
        stream.put_slice(&[7; 65527]);
        stream.put_slice(&[0, 0x80, 1, 0, 0, 1]);
        stream.put_slice(&[0; 65535]);
        let values = feed(&mut Decoder::default(), &stream, 4096);
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].len(), 65528);
        assert_eq!(values[1].len(), 65535);

        // A Context ID 0 capsule too large for a UDP payload aborts (RFC 9298 §5).
        let mut buf = BytesMut::from(&[0, 0x80, 1, 0, 0, 0][..]);
        assert!(matches!(
            Decoder::default().decode(&mut buf),
            Err(MasqueError::Malformed)
        ));

        // An oversized capsule is decided once its Context ID arrives: 0 aborts, others skip.
        let mut decoder = Decoder::default();
        let mut buf = BytesMut::new();
        for byte in [0, 0x80, 1, 0, 0] {
            buf.put_u8(byte);
            assert_eq!(decoder.decode(&mut buf).unwrap(), None);
        }
        assert_eq!(buf.len(), 5);
        let mut abort = buf.clone();
        abort.put_u8(0);
        assert!(matches!(
            decoder.decode(&mut abort),
            Err(MasqueError::Malformed)
        ));
        buf.put_u8(1);
        assert_eq!(decoder.decode(&mut buf).unwrap(), None);
        buf.put_slice(&[0; 65535]);
        encode_datagram(b"x", &mut buf);
        assert_eq!(decoder.decode(&mut buf).unwrap().unwrap(), &b"\0x"[..]);

        // Streams cut inside a buffered or a skipped capsule are partial.
        let mut decoder = Decoder::default();
        let mut buf = BytesMut::from(&[0, 4, 0, b'c', b'u'][..]);
        assert_eq!(decoder.decode(&mut buf).unwrap(), None);
        assert!(decoder.is_partial(&buf));
        let mut buf = BytesMut::from(&[0x40, 0x40, 10, 1, 2, 3][..]);
        assert_eq!(decoder.decode(&mut buf).unwrap(), None);
        assert!(buf.is_empty());
        assert!(decoder.is_partial(&buf));
    }
}
