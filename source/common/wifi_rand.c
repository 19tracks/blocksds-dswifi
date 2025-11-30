// A reseedable, hopefully cryptographically secure random number generator
// made from a modified version of BLAKE2Xs: https://www.blake2.net/blake2x.pdf

// If we didn't break anything, it should have a security level of 128 bits,
// just as BLAKE2 and BLAKE3 do.

// This code is based on the BLAKE2 reference C implementation by Samuel Neves,
// which was released under the CC0 1.0 Universal public domain dedication.

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "wifi_rand.h"

#ifdef ARM9
#define CACHE_ALIGNED __attribute__ ((aligned (32)))
#else
#define CACHE_ALIGNED
#endif

// Internals:

static const uint32_t Wifi_Rand_Iv[8] CACHE_ALIGNED =
{
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

// DEVIATION FROM BLAKE2Xs: We use BLAKE3's simpler key schedule.
// This schedule was deemed appropriate for BLAKE3's compression function
// because of its number of rounds and lack of constants in G, and our
// compression function shares both of those properties.
static const uint8_t Wifi_Rand_Sigma[16] CACHE_ALIGNED =
{
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

static void Wifi_Rand_SetLastnode(Wifi_Rand_State *S)
{
    S->f[1] = (uint32_t)-1;
}

static int Wifi_Rand_IsLastblock(const Wifi_Rand_State *S)
{
    return S->f[0] != 0;
}

static void Wifi_Rand_SetLastblock(Wifi_Rand_State *S)
{
    if (S->lastNode) Wifi_Rand_SetLastnode(S);

    S->f[0] = (uint32_t)-1;
}

static void Wifi_Rand_IncrementCounter(Wifi_Rand_State *S, const uint32_t inc)
{
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

static void Wifi_Rand_Init0(Wifi_Rand_State *S)
{
    memset(S, 0, sizeof(Wifi_Rand_State));
    memcpy(S->h, Wifi_Rand_Iv, sizeof(Wifi_Rand_Iv));
    S->inputCounter = 1;
}

static void Wifi_Rand_InitCounter(Wifi_Rand_State *S, const uint32_t counter)
{
    Wifi_Rand_Init0(S);
    // DEVIATION FROM BLAKE2Xs: We use a 32-bit counter in place of a 256-bit
    // parameter block. The other parameters in BLAKE2s's parameter block are
    // important for a hash function but irrelevant for an RNG.
    S->h[0] ^= counter;
}

static inline uint32_t rotr32(const uint32_t w, const unsigned c)
{
    return (w >> c) | (w << (32 - c));
}

#define G(m, i, a, b, c, d)                      \
    do {                                    \
        a = a + b + m[2 * i + 0];           \
        d = rotr32(d ^ a, 16);              \
        c = c + d;                          \
        b = rotr32(b ^ c, 12);              \
        a = a + b + m[2 * i + 1];           \
        d = rotr32(d ^ a, 8);               \
        c = c + d;                          \
        b = rotr32(b ^ c, 7);               \
    } while(0)

#define ROUND(m)                             \
    do {                                     \
        G(m, 0, v[ 0], v[ 4], v[ 8], v[12]); \
        G(m, 1, v[ 1], v[ 5], v[ 9], v[13]); \
        G(m, 2, v[ 2], v[ 6], v[10], v[14]); \
        G(m, 3, v[ 3], v[ 7], v[11], v[15]); \
        G(m, 4, v[ 0], v[ 5], v[10], v[15]); \
        G(m, 5, v[ 1], v[ 6], v[11], v[12]); \
        G(m, 6, v[ 2], v[ 7], v[ 8], v[13]); \
        G(m, 7, v[ 3], v[ 4], v[ 9], v[14]); \
    } while (0)

static void Wifi_Rand_Compress(Wifi_Rand_State *S, const uint8_t in[WIFI_RAND_BLOCKBYTES])
{
    uint32_t m_1[16], m_2[16];
    uint32_t v[16];

    memcpy(m_1, in, sizeof(m_1));

    memcpy(v, S->h, sizeof(S->h));
    memcpy(&v[8], Wifi_Rand_Iv, sizeof(v[8]) * 4);
    v[12] = S->t[0] ^ Wifi_Rand_Iv[4];
    v[13] = S->t[1] ^ Wifi_Rand_Iv[5];
    v[14] = S->f[0] ^ Wifi_Rand_Iv[6];
    v[15] = S->f[1] ^ Wifi_Rand_Iv[7];

    // DEVIATION FROM BLAKE2Xs: We use 7 rounds instead of 10. This number
    // was chosen for BLAKE3 based on years of cryptanalysis suggesting that 7
    // would be enough to make BLAKE2s secure. Reducing the number of rounds as
    // much as possible is important for us because of our limited processing
    // power.
    for (size_t i = 0; ;)
    {
        ROUND(m_1);

        // We check here instead of at the end of the loop because each loop
        // performs two rounds and our number of rounds is odd.
        if (i + 1 >= 7) break;

        for (size_t j = 0; j < 16; ++j)
        {
            m_2[j] = m_1[Wifi_Rand_Sigma[j]];
        }

        ROUND(m_2);

        for (size_t j = 0; j < 16; ++j)
        {
            m_1[j] = m_2[Wifi_Rand_Sigma[j]];
        }

        i += 2;
    }

    for (size_t i = 0; i < 8; ++i)
    {
        S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
    }
}

#undef G
#undef ROUND

// A change worth noting that we did not adopt from BLAKE3:
// Our compression function only produces 256 bits, as BLAKE2s's does.
// BLAKE3's longer output is meant to make it faster to use as an XOF, which on
// its face sounds very useful here, but it does so by generating more bytes at
// a time, which actually causes each RNG generation step to take slightly
// longer and requires a larger buffer. The 256-bit output of BLAKE2s's
// compression function is already enough to generate a 256-bit key or seed a
// ChaCha CSPRNG. Raw RNG throughput should not be a bottleneck, whereas the
// worst-case performance of a single invocation may be. The longer output also
// adds subtle complications to the security properies of the compression
// function, which we can sidestep having to confidently reason about by not
// implementing it.
static void Wifi_Rand_InnerFinish(Wifi_Rand_State *S, void *out, size_t outlen)
{
    assert(out != NULL);
    assert(!Wifi_Rand_IsLastblock(S));

    Wifi_Rand_IncrementCounter(S, (uint32_t)S->buflen);
    Wifi_Rand_SetLastblock(S);
    memset(S->buf + S->buflen, 0, WIFI_RAND_BLOCKBYTES - S->buflen); // Padding
    Wifi_Rand_Compress(S, S->buf);

    memcpy(out, S->h, outlen);
}

// External API:

void Wifi_Rand_Init(Wifi_Rand_State *S)
{
    Wifi_Rand_InitCounter(S, 0);
}

bool Wifi_Rand_WillUpdateTriggerCompress(Wifi_Rand_State *S, size_t inlen) {
    size_t fill = WIFI_RAND_BLOCKBYTES - S->buflen;
    return inlen > fill;
}

void Wifi_Rand_Update(Wifi_Rand_State *S, const void *pin, size_t inlen)
{
    const unsigned char *in = (const unsigned char *)pin;

    S->inputCounter += inlen;

    size_t left = S->buflen;
    size_t fill = WIFI_RAND_BLOCKBYTES - left;
    if (Wifi_Rand_WillUpdateTriggerCompress(S, inlen))
    {
        S->buflen = 0;
        memcpy(S->buf + left, in, fill);
        Wifi_Rand_IncrementCounter(S, WIFI_RAND_BLOCKBYTES);
        Wifi_Rand_Compress(S, S->buf);
        in += fill; inlen -= fill;
        while (inlen > WIFI_RAND_BLOCKBYTES)
        {
            Wifi_Rand_IncrementCounter(S, WIFI_RAND_BLOCKBYTES);
            Wifi_Rand_Compress(S, in);
            in += WIFI_RAND_BLOCKBYTES;
            inlen -= WIFI_RAND_BLOCKBYTES;
        }
    }
    memcpy(S->buf + S->buflen, in, inlen);
    S->buflen += inlen;
}

// This isn't really a deviation, but it is worth pointing out. When we finish
// a hasher, we leave it unchanged and write the finished state into a separate
// struct. This allows us to go back, add more bytes, and finish it again. Since
// the hasher is deterministic, this is equivalent to keeping track of
// everything that's been fed to the hasher, going back, and feeding it in again
// plus some new bytes into a new hasher; it's just faster and takes less
// memory.
void Wifi_Rand_Finish(Wifi_Rand_State *S, Wifi_Rand_FinishedState *F)
{
    // Finalize the root hash
    Wifi_Rand_State rootHasher;
    memcpy(&rootHasher, S, sizeof(rootHasher));
    Wifi_Rand_InnerFinish(&rootHasher, F->root, WIFI_RAND_OUTBYTES);
    F->buflen = 0;
    F->counter = 0;
    F->inputCounter = S->inputCounter;
}

static void Wifi_Rand_FinishedReadBlock(Wifi_Rand_FinishedState *F, uint8_t out[WIFI_RAND_OUTBYTES])
{
    Wifi_Rand_State xofHasher;

    // Pre-increment so we never use 0, as that's the counter we
    // use pre-finalization
    // DEVIATION FROM BLAKE2Xs: BLAKE2Xs starts the counter at 0;
    // we start it at 1.
    Wifi_Rand_InitCounter(&xofHasher, ++F->counter);
    Wifi_Rand_Update(&xofHasher, F->root, WIFI_RAND_OUTBYTES);
    Wifi_Rand_InnerFinish(&xofHasher, out, WIFI_RAND_OUTBYTES);
}

void Wifi_Rand_FinishedReadBytes(Wifi_Rand_FinishedState *F, void *outv, size_t outlen)
{
    uint8_t *out = outv;

    assert(out != NULL);

    // If outlen is a multiple of the output block size (which is
    // likely if using 256-bit cryptography, since the output block
    // size is 256 bits), avoid touching whatever's in the buffer
    // and just push bytes directly. The stream is supposed to be
    // unpredictable and irreproducible, so it doesn't matter that
    // this can result in us producing bytes out of order; all that
    // matters is that they're never reused.
    if (outlen % WIFI_RAND_OUTBYTES > 0)
    {
        if (outlen <= F->buflen)
        {
            memcpy(out, &F->buf[WIFI_RAND_OUTBYTES - F->buflen], outlen);
            F->buflen -= outlen;
            return;
        }

        memcpy(out, &F->buf[WIFI_RAND_OUTBYTES - F->buflen], F->buflen);
        out += F->buflen;
        outlen -= F->buflen;
        F->buflen = 0;
    }

    while (outlen >= WIFI_RAND_OUTBYTES)
    {
        Wifi_Rand_FinishedReadBlock(F, out);
        out += WIFI_RAND_OUTBYTES;
        outlen -= WIFI_RAND_OUTBYTES;
    }

    if (outlen > 0)
    {
        Wifi_Rand_FinishedReadBlock(F, F->buf);
        memcpy(out, F->buf, outlen);
        F->buflen = WIFI_RAND_OUTBYTES - outlen;
    }
}
