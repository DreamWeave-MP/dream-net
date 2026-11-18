/*
    dream-net fuzz harness support. SPDX-License-Identifier: MIT OR Apache-2.0

    Shared by the native fuzz harnesses in this directory (fuzz_*.c), which are test-only C:
    build.rs never compiles csrc/test/ into the archive. Each harness is a unity build over the
    vendored C (so it can reach netcode's and reliable's internal entry points) and defines
    LLVMFuzzerTestOneInput.

    Two ways to build one (tools/fuzz-native does both; tests/native_fuzz.rs the second):

    - with clang -fsanitize=fuzzer[,address,undefined]: a libFuzzer target;
    - with -DDN_FUZZ_STANDALONE: a deterministic driver whose main() runs a fixed number of
      seeded pseudo-random inputs (--iterations N --seed S --max-len L), or replays the input
      files named on the command line, then prints "<name>: N inputs OK". cargo test runs this
      form as the fuzz smoke, so CI keeps exercising every harness.

    Assertions: in the production configuration (NDEBUG) netcode_assert and reliable_assert
    compile to nothing. Built without NDEBUG (the "asserts live" configuration), every harness
    installs dn_fuzz_assert_trip as both libraries' assert handler: it prints one
    "DN-ASSERT-TRIP" line and aborts, so libFuzzer records the input as a crash and the trip
    is counted. An input that trips a live assert is one whose production behaviour rests on
    something other than that assert.
*/

#ifndef DN_FUZZ_SUPPORT_H
#define DN_FUZZ_SUPPORT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size );

/* A broken harness invariant: always fatal, in every configuration. */
#define DN_CHECK( condition )                                                               \
do                                                                                          \
{                                                                                           \
    if ( !(condition) )                                                                     \
    {                                                                                       \
        fprintf( stderr, "DN-CHECK failed: ( %s ), file %s, line %d\n",                     \
            #condition, __FILE__, __LINE__ );                                               \
        abort();                                                                            \
    }                                                                                       \
} while(0)

static inline void dn_fuzz_assert_trip( const char * condition, const char * function, const char * file, int line )
{
    fprintf( stderr, "DN-ASSERT-TRIP ( %s ), function %s, file %s, line %d\n",
             condition ? condition : "?", function ? function : "?", file ? file : "?", line );
    abort();
}

static inline int dn_fuzz_discard_printf( const char * format, ... )
{
    (void) format;
    return 0;
}

/* Reads little-endian values from the fuzz input, returning zeros once it runs dry. */

struct dn_in
{
    const uint8_t * data;
    size_t size;
    size_t offset;
};

static inline int dn_more( struct dn_in * in )
{
    return in->offset < in->size;
}

static inline uint8_t dn_u8( struct dn_in * in )
{
    if ( in->offset >= in->size )
        return 0;
    return in->data[in->offset++];
}

static inline uint16_t dn_u16( struct dn_in * in )
{
    uint16_t value = dn_u8( in );
    value |= (uint16_t) ( (uint16_t) dn_u8( in ) << 8 );
    return value;
}

static inline uint32_t dn_u32( struct dn_in * in )
{
    uint32_t value = 0;
    int i;
    for ( i = 0; i < 4; i++ )
        value |= ( (uint32_t) dn_u8( in ) ) << ( 8 * i );
    return value;
}

static inline uint64_t dn_u64( struct dn_in * in )
{
    uint64_t value = 0;
    int i;
    for ( i = 0; i < 8; i++ )
        value |= ( (uint64_t) dn_u8( in ) ) << ( 8 * i );
    return value;
}

static inline void dn_bytes( struct dn_in * in, uint8_t * out, size_t bytes )
{
    size_t i;
    for ( i = 0; i < bytes; i++ )
        out[i] = dn_u8( in );
}

/* Named counters a harness bumps to show how deep the inputs reach; the standalone driver
   prints the non-zero ones, so a smoke run that never reaches a state is visible. */
#define DN_STATS 8
static uint64_t dn_stats[DN_STATS];
static const char * dn_stat_names[DN_STATS];

static inline void dn_stat( int index, const char * name )
{
    dn_stats[index]++;
    dn_stat_names[index] = name;
}

/* FNV-1a, for remembering datagrams and payloads by value. */
static inline uint64_t dn_hash( const uint8_t * data, size_t bytes )
{
    uint64_t h = 0xcbf29ce484222325ULL;
    size_t i;
    for ( i = 0; i < bytes; i++ )
    {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h ^ (uint64_t) bytes;
}

#ifdef DN_FUZZ_STANDALONE

#ifndef DN_FUZZ_NAME
#define DN_FUZZ_NAME "fuzz"
#endif

static uint64_t dn_rng_state;

static uint64_t dn_rng( void )
{
    /* xorshift64* */
    dn_rng_state ^= dn_rng_state >> 12;
    dn_rng_state ^= dn_rng_state << 25;
    dn_rng_state ^= dn_rng_state >> 27;
    return dn_rng_state * 0x2545F4914F6CDD1DULL;
}

int main( int argc, char ** argv )
{
    long iterations = 0;
    uint64_t seed = 1;
    size_t max_len = 4096;
    int files = 0;
    int i;
    for ( i = 1; i < argc; i++ )
    {
        if ( strcmp( argv[i], "--iterations" ) == 0 && i + 1 < argc )
            iterations = strtol( argv[++i], NULL, 10 );
        else if ( strcmp( argv[i], "--seed" ) == 0 && i + 1 < argc )
            seed = strtoull( argv[++i], NULL, 10 );
        else if ( strcmp( argv[i], "--max-len" ) == 0 && i + 1 < argc )
            max_len = (size_t) strtoull( argv[++i], NULL, 10 );
        else
        {
            FILE * file = fopen( argv[i], "rb" );
            if ( !file )
            {
                fprintf( stderr, "could not open %s\n", argv[i] );
                return 1;
            }
            fseek( file, 0, SEEK_END );
            long file_size = ftell( file );
            fseek( file, 0, SEEK_SET );
            uint8_t * data = (uint8_t*) malloc( file_size > 0 ? (size_t) file_size : 1 );
            size_t bytes_read = fread( data, 1, file_size > 0 ? (size_t) file_size : 0, file );
            fclose( file );
            LLVMFuzzerTestOneInput( data, bytes_read );
            free( data );
            files++;
        }
    }
    if ( max_len == 0 )
        max_len = 1;
    dn_rng_state = seed ? seed : 1;
    uint8_t * buffer = (uint8_t*) malloc( max_len );
    long n;
    for ( n = 0; n < iterations; n++ )
    {
        size_t len = (size_t) ( dn_rng() % ( max_len + 1 ) );
        size_t k;
        for ( k = 0; k < len; k++ )
            buffer[k] = (uint8_t) ( dn_rng() >> 56 );
        LLVMFuzzerTestOneInput( buffer, len );
    }
    free( buffer );
    for ( i = 0; i < DN_STATS; i++ )
    {
        if ( dn_stats[i] )
            printf( "%s: %s %llu\n", DN_FUZZ_NAME, dn_stat_names[i], (unsigned long long) dn_stats[i] );
    }
    printf( "%s: %ld inputs OK\n", DN_FUZZ_NAME, iterations + files );
    return 0;
}

#endif /* DN_FUZZ_STANDALONE */

#endif /* DN_FUZZ_SUPPORT_H */
