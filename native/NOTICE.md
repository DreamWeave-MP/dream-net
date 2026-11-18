# Third-party notices for dream-net-native

dream-net-native compiles and ships C code from three upstream projects. Their notices are
reproduced below verbatim (the license text blocks are byte-for-byte copies of the vendored
files, checked by `tests/build_vendor.rs`), as their licenses require for both source and binary
redistribution. Any product that ships a binary containing dream-net-native, including dream-net
and everything built on it, must carry these notices in its documentation or other materials.

The crate's own Rust code, C shim (`csrc/`) and scripts (`tools/`) are MIT OR Apache-2.0
(`LICENSE-MIT`, `LICENSE-APACHE`). `LICENSES.md` lists the license of every file in the package.

Más Bandwidth also asks, without requiring it, that products credit "netcode - Glenn Fiedler and
Rowan Claude" and "reliable - Glenn Fiedler and Rowan Claude" (the request in `netcode.h` and
`reliable.h`). dream-net honours it.

## netcode (https://github.com/mas-bandwidth/netcode, v1.4.10)

Applies to `vendor/netcode/netcode.c`, `vendor/netcode/netcode.h`, `vendor/netcode/test.cpp`
and `vendor/netcode/sodium/NOTES.md` (netcode's notes on its libsodium subset). Text:
`vendor/netcode/LICENCE`.

```text
Copyright © 2017 - 2026, Más Bandwidth LLC

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer 
       in the documentation and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived 
       from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## reliable (https://github.com/mas-bandwidth/reliable, v1.4.6)

Applies to `vendor/reliable/reliable.c`, `vendor/reliable/reliable.h`,
`vendor/reliable/test.cpp`. Text: `vendor/reliable/LICENCE`.

```text
Copyright © 2017 - 2026, Más Bandwidth LLC

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer 
       in the documentation and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived 
       from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## libsodium (https://github.com/jedisct1/libsodium), subset bundled by netcode

Applies to `vendor/netcode/sodium/sodium.c` and `vendor/netcode/sodium/sodium.h`, an
amalgamated subset of libsodium 1.0.17-1.0.22 that netcode distributes (see `SODIUM.md`). The
text is the ISC notice that heads both files; libsodium's own `LICENSE` file at 1.0.22 is
byte-for-byte the same comment.

```text
/*
 * ISC License
 *
 * Copyright (c) 2013-2026
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
```

The ChaCha20 reference implementation inside `sodium.c` additionally carries the author's
dedication to the public domain, reproduced as it appears there:

```text
 chacha-merged.c version 20080118
 D. J. Bernstein
 Public domain.
```
