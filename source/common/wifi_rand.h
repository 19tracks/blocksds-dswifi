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

typedef struct Wifi_Rand_State__
{
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[WIFI_RAND_BLOCKBYTES];
    size_t   buflen;
    uint8_t  lastNode;
    // This counter starts at 1 so that it always compares greater than 0.
    uint32_t inputCounter;
} Wifi_Rand_State;

// buflen still stores the number of bytes in the buffer, but those bytes end
// at buf[WIFI_RAND_OUTBYTES] instead of starting at buf[0].
typedef struct Wifi_Rand_FinishedState__
{
    uint8_t  root[WIFI_RAND_OUTBYTES];
    uint8_t  buf[WIFI_RAND_OUTBYTES];
    size_t   buflen;
    uint32_t counter;
    uint32_t inputCounter;
} Wifi_Rand_FinishedState;

// Initialize a hasher. No entropy is sampled; the state the hasher is left in
// after this function is called is always the same.
void Wifi_Rand_Init(Wifi_Rand_State *state);
// Check whether any expensive compression steps will be triggered by a call to
// Wifi_Rand_Update with the given inlen. If this returns false, such a call to
// Wifi_Rand_Update will only copy inlen bytes into its internal buffer and
// update bookkeeping.
bool Wifi_Rand_WillUpdateTriggerCompress(Wifi_Rand_State *state, size_t inlen);
// Add the given bytes to state. If the internal buffer would overflow, the
// compression function is called as many times as necessary to absorb the
// entropy from every byte.
void Wifi_Rand_Update(Wifi_Rand_State *state, const void *in, size_t inlen);
// Create a Wifi_Rand_FinishedState from the current state. state is unchanged,
// and finished is freshly initialized. This runs the compression function.
void Wifi_Rand_Finish(Wifi_Rand_State *state, Wifi_Rand_FinishedState *finished);

// Check whether any expensive compression steps will be triggered by a call to
// Wifi_Rand_FinishedReadBytes with the given outlen. If this returns false,
// such a call to Wifi_Rand_FinishedReadBytes will only copy outlen bytes from
// its internal buffer and update bookkeeping.
bool Wifi_Rand_WillFinishedReadTriggerCompress(Wifi_Rand_FinishedState *state, size_t outlen);
// Read outlen pseudorandom bytes. The stream of bytes given as output will be
// unique to the stream of bytes that were given as input to the Wifi_Rand_State
// that was used to create this Wifi_Rand_FinishedState, and a given
// Wifi_Rand_FinishedState will never produce the same sequence of bytes
// multiple times except by chance or after producing 128 GiB (at which point
// the output loops). If the request can't be fulfilled from the internal
// buffer, the compression function is called as many times as necessary to
// fulfill it.
void Wifi_Rand_FinishedReadBytes(Wifi_Rand_FinishedState *finished, void *out, size_t outlen);

// Initialize `reservation` as a fork of `finished` and advance the byte stream
// `finished` far enough to make sure `finished` and `reservation` don't produce
// any of the same bytes unless by chance. Do not use `reservation` to read more
// than `outlen` bytes before discarding it, or this guarantee may not hold.
// Avoid passing excessively large values of `outlen` as well; the limit of
// 128 GiB of output before a Wifi_Rand_FinishedState loops is normally an
// astronomically large number of bytes for a DS, but hitting that limit becomes
// much more feasible if this function is abused.
void Wifi_Rand_FinishedReserveBytes(Wifi_Rand_FinishedState *finished, Wifi_Rand_FinishedState *reservation, size_t outlen);
// Add bytes from the internal buffer of `reservation` to the internal buffer of
// `finished`. Call this before discarding `reservation` so the processing time
// spent generating those bytes isn't wasted.
void Wifi_Rand_FinishedEndReservation(Wifi_Rand_FinishedState *finished, Wifi_Rand_FinishedState *reservation);

#endif
