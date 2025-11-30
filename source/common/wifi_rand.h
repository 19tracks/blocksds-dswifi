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
    uint8_t  last_node;
} Wifi_Rand_State;

// buflen still stores the number of bytes in the buffer, but those bytes end
// at buf[WIFI_RAND_OUTBYTES] instead of starting at buf[0].
typedef struct Wifi_Rand_FinishedState__
{
    uint8_t  root[WIFI_RAND_OUTBYTES];
    uint8_t  buf[WIFI_RAND_OUTBYTES];
    size_t   buflen;
    uint32_t counter;
} Wifi_Rand_FinishedState;

void Wifi_Rand_Init(Wifi_Rand_State *S);
bool Wifi_Rand_WillUpdateTriggerCompress(Wifi_Rand_State *S, size_t inlen);
void Wifi_Rand_Update(Wifi_Rand_State *S, const void *in, size_t inlen);
void Wifi_Rand_Finish(Wifi_Rand_State *S, Wifi_Rand_FinishedState *F);
void Wifi_Rand_FinishedReadBytes(Wifi_Rand_FinishedState *F, void *out, size_t outlen);

#endif
