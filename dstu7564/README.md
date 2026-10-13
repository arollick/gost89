# DSTU 7564 Uint32 port

Derived from npm `dstu7564` 1.1.0 (Illya Petrov / PrivatBank Cryptonite).
The public hash, streaming and KMAC API is unchanged. Each 64-bit round
word is represented by two Uint32 words; addition includes carry and wraps
modulo 2^64. The original S-box/MDS tables and streaming/KMAC construction
are retained. No native addon or 64-bit integer runtime is required.

The compatibility provider imports this bundled implementation directly.
Consumers can use the same API via `require('gost89/dstu7564')`.
There is no external dstu7564 runtime dependency or local file symlink.
KDF iteration counts, PFX MAC authentication and padding checks are unchanged.

Run `npm test` in the gost89 root. Passing hash vectors or Linux ia32 tests
does not validate the final Windows executable; test it on the target machine.
