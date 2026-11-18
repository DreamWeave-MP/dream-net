/*
    dream-net-native C shim. SPDX-License-Identifier: MIT OR Apache-2.0
*/

#include "dn_native_shim.h"

#include "netcode.h"
#include "reliable.h"

#include <stdio.h>
#include <stdlib.h>

/* NETCODE_CONST and RELIABLE_CONST expand to const in standard C, so these match the hooks'
   declared types exactly. */
static void dn_native_assert_abort( const char * condition, const char * function, const char * file, int line )
{
    /* One line to stderr, then abort(): a failed invariant must not continue into undefined
       behaviour, and the message is the only diagnostic a crash report will carry. */
    fprintf( stderr, "dream-net-native: C assertion failed: ( %s ), function %s, file %s, line %d\n",
             condition ? condition : "?", function ? function : "?", file ? file : "?", line );
    fflush( stderr );
    abort();
}

static int dn_native_printf_discard( const char * format, ... )
{
    (void) format;
    return 0;
}

void dn_native_hooks_install( void )
{
    netcode_set_assert_function( dn_native_assert_abort );
    reliable_set_assert_function( dn_native_assert_abort );
    netcode_set_printf_function( dn_native_printf_discard );
    reliable_set_printf_function( dn_native_printf_discard );
    netcode_log_level( NETCODE_LOG_LEVEL_NONE );
    reliable_log_level( RELIABLE_LOG_LEVEL_NONE );
}

uint32_t dn_native_probe_mix( uint32_t x )
{
    return ( x ^ 0x9E3779B9u ) * 0x85EBCA6Bu;
}
