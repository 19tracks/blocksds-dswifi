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

// internals:

static const uint32_t Wifi_Rand_Iv[8] CACHE_ALIGNED =
{
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t Wifi_Rand_Sigma[16] CACHE_ALIGNED =
{
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

static void Wifi_Rand_SetLastnode( Wifi_Rand_State *S )
{
  S->f[1] = (uint32_t)-1;
}

/* Some helper functions, not necessarily useful */
static int Wifi_Rand_IsLastblock( const Wifi_Rand_State *S )
{
  return S->f[0] != 0;
}

static void Wifi_Rand_SetLastblock( Wifi_Rand_State *S )
{
  if( S->last_node ) Wifi_Rand_SetLastnode( S );

  S->f[0] = (uint32_t)-1;
}

static void Wifi_Rand_IncrementCounter( Wifi_Rand_State *S, const uint32_t inc )
{
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
}

static void Wifi_Rand_Init0( Wifi_Rand_State *S )
{
  memset( S, 0, sizeof( Wifi_Rand_State ) );
  memcpy( S->h, Wifi_Rand_Iv, sizeof(Wifi_Rand_Iv) );
}

/* init2 xors IV with input parameter block */
static void Wifi_Rand_InitCounter( Wifi_Rand_State *S, const uint32_t counter )
{
  Wifi_Rand_Init0( S );
  S->h[0] ^= counter;
}

static inline uint32_t rotr32( const uint32_t w, const unsigned c )
{
  return ( w >> c ) | ( w << ( 32 - c ) );
}

#define G(m,i,a,b,c,d)                      \
  do {                                      \
    a = a + b + m[2*i+0];                   \
    d = rotr32(d ^ a, 16);                  \
    c = c + d;                              \
    b = rotr32(b ^ c, 12);                  \
    a = a + b + m[2*i+1];                   \
    d = rotr32(d ^ a, 8);                   \
    c = c + d;                              \
    b = rotr32(b ^ c, 7);                   \
  } while(0)

#define ROUND(m)                    \
  do {                              \
    G(m,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(m,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(m,2,v[ 2],v[ 6],v[10],v[14]); \
    G(m,3,v[ 3],v[ 7],v[11],v[15]); \
    G(m,4,v[ 0],v[ 5],v[10],v[15]); \
    G(m,5,v[ 1],v[ 6],v[11],v[12]); \
    G(m,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(m,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)

static void Wifi_Rand_Compress( Wifi_Rand_State *S, const uint8_t in[WIFI_RAND_BLOCKBYTES] )
{
  uint32_t m_1[16], m_2[16];
  uint32_t v[16];
  size_t i, j;

  memcpy( m_1, in, sizeof(m_1) );

  memcpy( v, S->h, sizeof(S->h) );
  memcpy( &v[8], Wifi_Rand_Iv, sizeof(v[8]) * 4 );
  v[12] = S->t[0] ^ Wifi_Rand_Iv[4];
  v[13] = S->t[1] ^ Wifi_Rand_Iv[5];
  v[14] = S->f[0] ^ Wifi_Rand_Iv[6];
  v[15] = S->f[1] ^ Wifi_Rand_Iv[7];

  for( i = 0; ; ) {
    ROUND( m_1 );

    // 7 rounds; check here because the number is odd.
    if( i + 1 >= 7 ) break;

    for( j = 0; j < 16; ++j ) {
      m_2[j] = m_1[Wifi_Rand_Sigma[j]];
    }

    ROUND( m_2 );

    for( j = 0; j < 16; ++j ) {
      m_1[j] = m_2[Wifi_Rand_Sigma[j]];
    }

    i += 2;
  }

  for( i = 0; i < 8; ++i ) {
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
  }
}

#undef G
#undef ROUND

static void Wifi_Rand_InnerFinish( Wifi_Rand_State *S, void *out, size_t outlen )
{
  assert( out != NULL);
  assert( !Wifi_Rand_IsLastblock( S ) );

  Wifi_Rand_IncrementCounter( S, ( uint32_t )S->buflen );
  Wifi_Rand_SetLastblock( S );
  memset( S->buf + S->buflen, 0, WIFI_RAND_BLOCKBYTES - S->buflen ); /* Padding */
  Wifi_Rand_Compress( S, S->buf );

  memcpy( out, S->h, outlen );
}

// external API:

void Wifi_Rand_Init( Wifi_Rand_State *S ) {
  Wifi_Rand_InitCounter( S, 0 );
}

void Wifi_Rand_Update( Wifi_Rand_State *S, const void *pin, size_t inlen )
{
  const unsigned char * in = (const unsigned char *)pin;
  if( inlen > 0 )
  {
    size_t left = S->buflen;
    size_t fill = WIFI_RAND_BLOCKBYTES - left;
    if( inlen > fill )
    {
      S->buflen = 0;
      memcpy( S->buf + left, in, fill ); /* Fill buffer */
      Wifi_Rand_IncrementCounter( S, WIFI_RAND_BLOCKBYTES );
      Wifi_Rand_Compress( S, S->buf ); /* Compress */
      in += fill; inlen -= fill;
      while(inlen > WIFI_RAND_BLOCKBYTES) {
        Wifi_Rand_IncrementCounter(S, WIFI_RAND_BLOCKBYTES);
        Wifi_Rand_Compress( S, in );
        in += WIFI_RAND_BLOCKBYTES;
        inlen -= WIFI_RAND_BLOCKBYTES;
      }
    }
    memcpy( S->buf + S->buflen, in, inlen );
    S->buflen += inlen;
  }
}

void Wifi_Rand_Finish(Wifi_Rand_State *S, Wifi_Rand_FinishedState *F) {
  /* Finalize the root hash */
  Wifi_Rand_State C[1];
  memcpy(C, S, sizeof(C));
  Wifi_Rand_InnerFinish(C, F->root, WIFI_RAND_OUTBYTES);
  F->buflen = 0;
  F->counter = 0;
}

static void Wifi_Rand_FinishedReadBlock(Wifi_Rand_FinishedState *F, uint8_t out[WIFI_RAND_OUTBYTES]) {
  Wifi_Rand_State C[1];

  /* Initialize state */
  // pre-increment so we never use 0, as that's the counter we
  // use pre-finalization
  Wifi_Rand_InitCounter(C, ++F->counter);
  /* Process key if needed */
  Wifi_Rand_Update(C, F->root, WIFI_RAND_OUTBYTES);
  Wifi_Rand_InnerFinish(C, out, WIFI_RAND_OUTBYTES);
}

void Wifi_Rand_FinishedReadBytes(Wifi_Rand_FinishedState *F, void *outv, size_t outlen) {
  uint8_t *out = outv;

  assert( out != NULL );
  assert( outlen != 0 );

  // if outlen is a multiple of the output block size (which is
  // likely if using 256-bit cryptography, since the output block
  // size is 256 bits), avoid touching whatever's in the buffer
  // and just push bytes directly. the stream is supposed to be
  // unpredictable and irreproducible, so it doesn't matter that
  // this can result in us producing bytes out of order; all that
  // matters is that they're never reused.
  if (outlen % WIFI_RAND_OUTBYTES > 0) {
    if (outlen <= F->buflen) {
      memcpy(out, &F->buf[WIFI_RAND_OUTBYTES - F->buflen], outlen);
      F->buflen -= outlen;
      return;
    }

    memcpy(out, &F->buf[WIFI_RAND_OUTBYTES - F->buflen], F->buflen);
    out += F->buflen;
    outlen -= F->buflen;
    F->buflen = 0;
  }

  while (outlen >= WIFI_RAND_OUTBYTES) {
    Wifi_Rand_FinishedReadBlock(F, out);
    out += WIFI_RAND_OUTBYTES;
    outlen -= WIFI_RAND_OUTBYTES;
  }

  if (outlen > 0) {
    Wifi_Rand_FinishedReadBlock(F, F->buf);
    memcpy(out, F->buf, outlen);
    F->buflen = WIFI_RAND_OUTBYTES - outlen;
  }
}
