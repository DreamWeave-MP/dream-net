/*
    dream-net C shim. SPDX-License-Identifier: MIT OR Apache-2.0

    Every external symbol defined here already carries the dn_native_ prefix, so the force-included
    dn_native_prefix.h leaves these names alone. build.rs compiles every top-level .c file in
    csrc/ into the native archive with -Werror; the binding workstreams add their shim files
    (configuration builders, trampolines, _Static_assert layout pins) next to this one.
*/

#ifndef DN_NATIVE_SHIM_H
#define DN_NATIVE_SHIM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
    Installs dream-net's process-wide policy on the vendored libraries. Call it once, before
    netcode_init and reliable_init, from the same serialised initialisation (see BUILD.md):

    - assertions: the archive is built with NDEBUG and RELIABLE_RELEASE in every profile, so
      netcode_assert and reliable_assert compile to nothing and the Rust wrappers validate what
      they guarded (BUILD.md, "Assertions"). The handler installed here only matters for a
      differently configured build: it writes one line to stderr and calls abort(), never
      returning into a broken invariant and never calling exit() or printing to stdout.
    - logging: both log levels are set to NONE and both printf hooks to a function that discards
      its arguments, so nothing reaches stdout even if a level is raised later without also
      installing a capturing hook.

    Idempotent; not thread-safe against concurrent calls into netcode or reliable.
*/
void dn_native_hooks_install( void );

/*
    The cross-language LTO probe (tools/lto-probe): a pure function with recognisable constants,
    so a disassembly shows whether Rust callers got it inlined. Not part of any API.
*/
uint32_t dn_native_probe_mix( uint32_t x );

#ifdef __cplusplus
}
#endif

#endif /* DN_NATIVE_SHIM_H */
