// netguard webgate: SHA-1 for the RFC 6455 opening handshake only.
//
// The fork deleted the WebSocket *transport* (`src/websocket.rs`, step 6-E) because it was an
// egress path to a hosted server. The web gateway needs the opposite half: a listener the operator
// binds on this machine, that a browser upgrades to, whose handshake answer is
// `base64(sha1(key + GUID))` over one 60-byte ASCII string.
//
// Pulling a crate in for that would add a dependency to the audited binary and re-open a
// dependency the acceptance notes say is gone. The compression function is ~40 lines, and the
// known-answer tests at the bottom of this file pin it against the FIPS-180-1 vectors, so it
// lives here instead. Nothing else in the product hashes with it: peer authentication uses
// Ed25519 + the RustDesk handshake, not this code.

/// Return the 20-byte FIPS-180-1 digest of `input`.
pub fn sha1(input: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BAD_CFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    // Padding: 0x80, then zeroes until the length is 56 mod 64, then the bit length (big endian).
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(input.len() + 72);
    msg.extend_from_slice(input);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for block in msg.chunks(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate().take(80) {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for i in 0..5 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sha1;

    fn hex(digest: &[u8; 20]) -> String {
        digest.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn webgate_sha1_matches_fips_vectors() {
        // FIPS-180-1's two published vectors, plus the two lengths where the padding crosses a
        // block boundary: 55 bytes fit one block with the length field, 56 do not. The last two
        // digests are against OpenSSL's SHA-1, not against this file.
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex(&sha1(&[b'a'; 55])),
            "c1c8bbdc22796e28c0e15163d20899b65621d65a"
        );
        assert_eq!(
            hex(&sha1(&[b'a'; 56])),
            "c2db330f6083854c99d4b5bfb6e8f29f201be699"
        );
        assert_eq!(
            hex(&sha1(&[b'a'; 64])),
            "0098ba824b5c16427bd7a1122a5a442a25ec644d"
        );
    }

    #[test]
    fn webgate_sha1_matches_websocket_sample() {
        // RFC 6455 §1.3: the demo nonce, with the handshake GUID appended, must base64 to the
        // demo `Sec-WebSocket-Accept`. This is the only use this digest has in the product.
        use hbb_common::base64::{engine::general_purpose::STANDARD, Engine as _};
        let digest = sha1(b"dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        assert_eq!(
            STANDARD.encode(digest),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
