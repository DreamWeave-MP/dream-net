# Third-party notices

dream-net itself is MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`). Every dream-net binary
also contains C code compiled from its dependency
[dream-net-native](https://crates.io/crates/dream-net-native), which vendors Más Bandwidth's
netcode and reliable (BSD-3-Clause) and the libsodium subset netcode bundles (ISC). Those
licenses are permissive; their one condition on binary redistribution is that the notices below
travel "in the documentation and/or other materials provided with the distribution". **Any
product that ships a binary built with dream-net (l3i, Jess, a game, a server) must reproduce
this file, or dream-net-native's `NOTICE.md`, which carries the same texts.**

The texts are reproduced here verbatim, byte for byte as dream-net-native ships them, so the
dream-net crate alone carries every notice a redistributor needs. `tools/check-native-licenses`
fails if they drift apart. The per-file license inventory of the vendored C is dream-net-native's
`LICENSES.md`.

Products and documentation that ship dream-net should carry this credit:

> Networking built on netcode, reliable and serialize by Más Bandwidth LLC
> (https://mas-bandwidth.com).

netcode and reliable also ask, without requiring it, that products credit "netcode - Glenn
Fiedler and Rowan Claude" and "reliable - Glenn Fiedler and Rowan Claude".

## netcode (C, v1.4.10, https://github.com/mas-bandwidth/netcode)

Compiled into every dream-net binary through dream-net-native (`vendor/netcode/`).

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

## reliable (C, v1.4.6, https://github.com/mas-bandwidth/reliable)

Compiled into every dream-net binary through dream-net-native (`vendor/reliable/`).

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

## libsodium (subset bundled by netcode, https://github.com/jedisct1/libsodium)

Compiled into every dream-net binary through dream-net-native (`vendor/netcode/sodium/`): an
amalgamated subset of libsodium 1.0.17-1.0.22 that provides netcode's ChaCha20-Poly1305 and
random numbers.

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

The ChaCha20 reference implementation inside it additionally carries the author's dedication to
the public domain, reproduced as it appears there:

```text
 chacha-merged.c version 20080118
 D. J. Bernstein
 Public domain.
```

## serialize (wire format, https://github.com/mas-bandwidth/serialize.rs)

No serialize code is compiled into dream-net. Its connection packets use serialize's bit-stream
format (wire format v2), written by dream-net's own `bits` module, which reimplements the part of
`serialize-official` 2.4.0 that dream-net 1.1.1 used, following its algorithms closely (bit
order, alignment, `int_relative`'s buckets) so that 1.1.1 peers interoperate unchanged. Keeping
serialize's notice is the conservative reading of that closeness, and costs a redistributor
nothing: it is the same Más Bandwidth BSD-3-Clause text as above.

```text
BSD 3-Clause License

Copyright (c) 2016 - 2026, Más Bandwidth LLC

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
