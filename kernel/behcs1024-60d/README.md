# Asolaria BEHCS-1024 / 60D clean mathematical kernel

Copied only the two PURE mathematical routines, fixed-buffer SHA-256 and project_60d, from the public Asolaria Federation 1024 source, commit `dc1da1a9cd88b77eb463053312b7c42a7dbe9b33`, file `kernel/boot/src/hwinv.rs` Git blob `d08bc2a9ba6f3b63fec5249f0670d68c8df744d4`. Same MIT OR Apache-2.0 terms as upstream. We did NOT copy rosters, network topology, operator information, host enumeration, serial output, keys or unrelated kernel files.

The source algorithm accepts up to 512 tuple bytes, appends four-byte big-endian counters 0,1,2,3, hashes each via a source SHA-256 routine capped at 512 bytes, and takes 60 10-bit masked glyphs (0..1023). Its 8-byte Host8-style label is the first 8 bytes of SHA-256 of 120 big-endian coordinate bytes.

**Reproducible mathematical defect:** for tuple lengths 509-512, the SHA cap drops some or all of the appended counter bytes. All counter rounds 0..3 hash the SAME bytes for each such tuple, so every 16-glyph block repeats. `project_60d_legacy` deliberately preserves the source result. `project_60d_checked` rejects lengths over 508, without rewriting any source identity. Original upstream is unchanged.

**Balanced ternary view:** each of 1024 glyph values maps reversibly to 7 trits (-1,0,+1). Since 3^6=729 < 1024 <= 3^7=2187, 7 trits are minimal fixed width. This is representation conversion, not ternary hashing. The coordinate label is not invertible back to the source and is not a physical 60-dimensional measurement. Its 8-byte digest prefix can collide.

The crate is no_std, Rust 1.81, no external crates, no float, Node.js or JSON transport. See `PROJECTION-60D.hbi`, `SOURCE-EVIDENCE.hbp`, `GOLDEN-VECTORS.hbp` and the SHA-256 sidecars. Independent Python hashlib and Rust tests must agree; check CI before claiming PASS. DH authentication and hardware attestation are NOT implemented.

Reproduce:
```sh
cargo +1.81 fmt --all -- --check
cargo +1.81 clippy --all-targets -- -D warnings
cargo +1.81 test --all
python3 tools/independent_vectors.py
python3 tools/privacy_scan.py
```
