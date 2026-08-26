# Vendored code

`inc_ecc_secp256k1.cl` / `inc_ecc_secp256k1.h` are copied unmodified from
[hashcat](https://github.com/hashcat/hashcat), `OpenCL/inc_ecc_secp256k1.{cl,h}`
(MIT license, see the header comment in each file). They implement secp256k1
field arithmetic and `point_mul_xy` (scalar multiplication by the base point
G, windowed-NAF), used by `gpu/bip32_tree.cl` for every EC operation in the
BIP32 derivation tree (every point in that tree is a scalar times G).

Not modified except that `#include "inc_ecc_secp256k1.h"` is stripped when
`gpu/bench_bip32.py` concatenates the OpenCL sources for compilation --
the header's content is prepended directly instead.
