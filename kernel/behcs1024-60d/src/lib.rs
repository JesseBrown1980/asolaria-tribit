#![no_std]
#![forbid(unsafe_code)]
//! Clean BEHCS-1024 60-glyph mathematical projection from pinned federation Rust.
//! Only pure SHA-256 and projection code was extracted. No operational inventory.
pub const DIMENSIONS: usize = 60;
pub const ALPHABET: u16 = 1024;
const TUPLE_CAP: usize = 512;
pub const MAX_COUNTER_SAFE_TUPLE: usize = TUPLE_CAP - 4;

/// SOURCE-FAITHFUL fixed-buffer SHA-256. Truncates inputs after byte 512.
/// This legacy routine must NOT be used as an arbitrary-length hash primitive.

pub fn sha256_legacy(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = [0u8; 640];
    let n = if data.len() > TUPLE_CAP {
        TUPLE_CAP
    } else {
        data.len()
    };
    msg[..n].copy_from_slice(&data[..n]);
    msg[n] = 0x80;
    let mut total = n + 1;
    while total % 64 != 56 {
        total += 1;
    }
    let bit_len = (n as u64).wrapping_mul(8);
    msg[total..total + 8].copy_from_slice(&bit_len.to_be_bytes());
    total += 8;

    let mut off = 0;
    while off < total {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let j = off + i * 4;
            *word = u32::from_be_bytes([msg[j], msg[j + 1], msg[j + 2], msg[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
        off += 64;
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Original algorithm: four SHA-256 blocks, first 60 two-byte big-endian chunks masked to 10 bits.
pub fn project_60d_legacy(tuple: &[u8]) -> [u16; 60] {
    let mut sel = [0u16; 60];
    let mut buf = [0u8; TUPLE_CAP + 4];
    let n = if tuple.len() > TUPLE_CAP {
        TUPLE_CAP
    } else {
        tuple.len()
    };
    buf[..n].copy_from_slice(&tuple[..n]);
    let (mut i, mut counter) = (0usize, 0u32);
    while i < 60 {
        buf[n..n + 4].copy_from_slice(&counter.to_be_bytes());
        let h = sha256_legacy(&buf[..n + 4]);
        let mut j = 0;
        while j + 1 < 32 && i < 60 {
            sel[i] = (((h[j] as u16) << 8) | h[j + 1] as u16) & 0x03FF;
            i += 1;
            j += 2;
        }
        counter += 1;
    }
    sel
}

/// Original output semantics, including the boundary bug when input >508 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionError { CounterNotFullyHashed }

/// Rejects tuples whose 4-byte salt would be dropped, partially or wholly.
pub fn project_60d_checked(input: &[u8]) -> Result<[u16; 60], ProjectionError> {
    if input.len() > MAX_COUNTER_SAFE_TUPLE {
        return Err(ProjectionError::CounterNotFullyHashed);
    }
    Ok(project_60d_legacy(input))
}
/// Serialize 60 indices as the 120 big-endian bytes hashed by the source Host8.
pub fn coordinate_bytes(coord: &[u16; 60]) -> [u8; 120] {
    let mut out = [0u8; 120];
    for (k, g) in coord.iter().enumerate() {
        out[k * 2..k * 2 + 2].copy_from_slice(&g.to_be_bytes());
    }
    out
}
/// Returns source-compatible first eight bytes of SHA-256(coordinate_bytes).
/// This is a truncated hash address, NOT an authentication or unique proof.
pub fn host8_from_coordinate(coord: &[u16; 60]) -> [u8; 8] {
    let digest = sha256_legacy(&coordinate_bytes(coord));
    let mut h = [0u8; 8];
    h.copy_from_slice(&digest[..8]);
    h
}
/// 0..1023 -> seven balanced trits. This view is bijective for the 1024 glyphs.
/// Native SHA-256 remains a binary hash, not a ternary cryptographic primitive.
pub fn glyph_to_trits(glyph: u16) -> Option<[i8; 7]> {
    if glyph >= ALPHABET { return None; }
    let mut n = usize::from(glyph);
    let mut trits = [0i8; 7];
    for t in trits.iter_mut().rev() {
        *t = (n % 3) as i8 - 1;
        n /= 3;
    }
    Some(trits)
}
pub fn trits_to_glyph(trits: &[i8; 7]) -> Option<u16> {
    let mut val = 0usize;
    for &t in trits {
        if !(-1..=1).contains(&t) { return None; }
        val = val * 3 + usize::try_from(t + 1).ok()?;
    }
    u16::try_from(val).ok().filter(|g| *g < ALPHABET)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_fips_known_vectors() {
        assert_eq!(&sha256_legacy(b"")[..4], &[0xe3,0xb0,0xc4,0x42]);
        assert_eq!(&sha256_legacy(b"abc")[..4], &[0xba,0x78,0x16,0xbf]);
    }
    #[test]
    fn source_60d_golden_abc() {
        let c = project_60d_checked(b"abc").unwrap();
        assert_eq!(&c[..8], &[813,428,103,701,206,505,788,597]);
        assert_eq!(host8_from_coordinate(&c), [0xff,0x50,0x4d,0x90,0x89,0x99,0x02,0xcd]);
    }
    #[test]
    fn source_60d_golden_empty() {
        let c = project_60d_checked(b"").unwrap();
        assert_eq!(&c[..8], &[831,408,169,987,87,301,61,840]);
        assert_eq!(host8_from_coordinate(&c), [0xa9,0x35,0x05,0xa9,0x5d,0x0a,0xac,0xe1]);
    }
    #[test]
    fn legacy_and_checked_agree_on_safe_domain() {
        for n in [0usize, 3, 17, 128, 508] {
            let input = [0x42u8; 508];
            assert_eq!(project_60d_checked(&input[..n]).unwrap(), project_60d_legacy(&input[..n]));
        }
    }
    #[test]
    fn 508_preserves_counter_domain_separation() {
        let c = project_60d_checked(&[0x42u8; 508]).unwrap();
        assert_ne!(&c[..16], &c[16..32]);
        assert_eq!(&c[..8], &[760,475,404,897,943,763,994,891]);
    }
    #[test]
    fn 509_to_512_repeats_counter_blocks_and_checked_rejects() {
        let input = [0x42u8; 512];
        for n in 509..=512 {
            let legacy = project_60d_legacy(&input[..n]);
            assert_eq!(&legacy[..16], &legacy[16..32]);
            assert_eq!(&legacy[16..32], &legacy[32..48]);
            assert_eq!(project_60d_checked(&input[..n]), Err(ProjectionError::CounterNotFullyHashed));
        }
    }
    #[test]
    fn 512_source_vector_and_host8() {
        let c = project_60d_legacy(&[0x42u8; 512]);
        assert_eq!(&c[..8], &[913,534,916,925,298,717,311,170]);
        assert_eq!(host8_from_coordinate(&c), [0x7f,0x51,0x9c,0xdf,0xba,0xbf,0x95,0xbc]);
    }
    #[test]
    fn ternary_1024_glyph_roundtrip_exhaustive() {
        for glyph in 0..ALPHABET {
            let trits = glyph_to_trits(glyph).unwrap();
            assert!(trits.iter().all(|t| (-1..=1).contains(t)));
            assert_eq!(trits_to_glyph(&trits), Some(glyph));
        }
        assert!(glyph_to_trits(ALPHABET).is_none());
        assert!(trits_to_glyph(&[1;7]).is_none());
        assert!(trits_to_glyph(&[-2;7]).is_none());
    }
    #[test]
    fn no_more_than_1023_per_glyph() {
        let c = project_60d_checked(b"demo").unwrap();
        assert!(c.iter().all(|g| *g < ALPHABET));
        assert_eq!(c.len(), DIMENSIONS);
    }
}
