// A reseedable, hopefully cryptographically secure random number generator
// made from a modified version of BLAKE2Xs: https://www.blake2.net/blake2x.pdf

// If we didn't break anything, it should have a security level of 128 bits,
// just as BLAKE2 and BLAKE3 do.

// This code is based on the BLAKE2 reference C implementation by Samuel Neves,
// which was released under the CC0 1.0 Universal public domain dedication.

#ifndef DSWIFI_COMMON_WIFI_RAND_WIFI_RAND_H__
#define DSWIFI_COMMON_WIFI_RAND_WIFI_RAND_H__

#include <stddef.h>
#include <stdint.h>

#define WIFI_RAND_BLOCKBYTES 64
#define WIFI_RAND_OUTBYTES   32

typedef struct Wifi_Rand_Hasher__
{
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[WIFI_RAND_BLOCKBYTES];
    size_t   buflen;
    uint8_t  lastNode;
    // This counter starts at 1 so that it always compares greater than 0.
    uint32_t inputCounter;
} Wifi_Rand_Hasher;

// buflen still stores the number of bytes in the buffer, but those bytes end
// at buf[WIFI_RAND_OUTBYTES] instead of starting at buf[0].
typedef struct Wifi_Rand_Generator__
{
    uint8_t  root[WIFI_RAND_OUTBYTES];
    uint8_t  buf[WIFI_RAND_OUTBYTES];
    size_t   buflen;
    uint32_t counter;
    uint32_t inputCounter;
} Wifi_Rand_Generator;

// Initialize a hasher. No entropy is sampled; the state the hasher is left in
// after this function is called is always the same.
void Wifi_Rand_InitHasher(Wifi_Rand_Hasher *hasher);
// If this returns true, a call to Wifi_Rand_Hash with the given inlen will only
// copy inlen bytes into its internal buffer and update bookkeeping; no
// expensive compression steps will be run.
bool Wifi_Rand_WillHashBeFast(Wifi_Rand_Hasher *hasher, size_t inlen);
// Add the given bytes to the hasher. If the internal buffer would overflow, the
// compression function is called as many times as necessary to absorb the
// entropy from every byte.
void Wifi_Rand_Hash(Wifi_Rand_Hasher *hasher, const void *in, size_t inlen);
// Create a generator from the current state of a hasher. hasher is unchanged,
// and generator is freshly initialized. This is slow, as it runs the
// compression function.
void Wifi_Rand_SpawnGenerator(Wifi_Rand_Hasher *hasher, Wifi_Rand_Generator *generator);

// If this returns true, a call to Wifi_Rand_Generate with the given outlen will
// only copy outlen bytes from its internal buffer and update bookkeeping; no
// expensive compression steps will be run.
bool Wifi_Rand_WillGenerateBeFast(Wifi_Rand_Generator *hasher, size_t outlen);
// Produce outlen pseudorandom bytes. The stream of bytes given as output across
// all invocations of this function on a given generator should be practically
// unique to the stream of bytes that were given as input to the hasher that was
// used to spawn it, and a given generator will never produce the same sequence
// of bytes multiple times except by chance or after producing 128 GiB (at which
// point the output loops). If the request can't be fulfilled from the internal
// buffer, the compression function is called as many times as necessary to
// fulfill it.
void Wifi_Rand_Generate(Wifi_Rand_Generator *generator, void *out, size_t outlen);

// Initialize reservation as a fork of generator and advance the byte stream of
// generator far enough to make sure generator and reservation don't produce any
// of the same bytes unless by chance. Do not use reservation to read more than
// outlen bytes before discarding it, or this guarantee may not hold. Avoid
// passing excessively large values of outlen as well; the limit of 128 GiB of
// output before a generator loops is normally an astronomically large number of
// bytes for a DS, but hitting that limit becomes much more feasible if this
// function is abused, as it advances the internal counter by any given number
// of bytes instantly.
void Wifi_Rand_Reserve(Wifi_Rand_Generator *generator, Wifi_Rand_Generator *reservation, size_t outlen);
// Add bytes from the internal buffer of reservation to the internal buffer of
// generator. Call this before discarding reservation so the processing time
// spent generating those bytes isn't wasted.
void Wifi_Rand_ReabsorbReservation(Wifi_Rand_Generator *generator, Wifi_Rand_Generator *reservation);

#endif
