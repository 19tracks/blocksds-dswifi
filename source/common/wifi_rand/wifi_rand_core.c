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

static const uint32_t Wifi_Rand_Core_Iv[8] CACHE_ALIGNED =
{
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t Wifi_Rand_Core_Sigma[16] CACHE_ALIGNED =
{
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

static void Wifi_Rand_Core_SetLastnode( Wifi_Rand_Core_State *S )
{
  S->f[1] = (uint32_t)-1;
}

/* Some helper functions, not necessarily useful */
static int Wifi_Rand_Core_IsLastblock( const Wifi_Rand_Core_State *S )
{
  return S->f[0] != 0;
}

static void Wifi_Rand_Core_SetLastblock( Wifi_Rand_Core_State *S )
{
  if( S->last_node ) Wifi_Rand_Core_SetLastnode( S );

  S->f[0] = (uint32_t)-1;
}

static void Wifi_Rand_Core_IncrementCounter( Wifi_Rand_Core_State *S, const uint32_t inc )
{
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
}

static void Wifi_Rand_Core_Init0( Wifi_Rand_Core_State *S )
{
  memset( S, 0, sizeof( Wifi_Rand_Core_State ) );
  memcpy( S->h, Wifi_Rand_Core_Iv, sizeof(Wifi_Rand_Core_Iv) );
}

/* init2 xors IV with input parameter block */
void Wifi_Rand_Core_InitCounter( Wifi_Rand_Core_State *S, const uint32_t counter )
{
  Wifi_Rand_Core_Init0( S );
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

static void Wifi_Rand_Core_Compress( Wifi_Rand_Core_State *S, const uint8_t in[WIFI_RAND_CORE_BLOCKBYTES] )
{
  uint32_t m_1[16], m_2[16];
  uint32_t v[16];
  size_t i, j;

  memcpy( m_1, in, sizeof(m_1) );

  memcpy( v, S->h, sizeof(S->h) );
  memcpy( &v[8], Wifi_Rand_Core_Iv, sizeof(v[8]) * 4 );
  v[12] = S->t[0] ^ Wifi_Rand_Core_Iv[4];
  v[13] = S->t[1] ^ Wifi_Rand_Core_Iv[5];
  v[14] = S->f[0] ^ Wifi_Rand_Core_Iv[6];
  v[15] = S->f[1] ^ Wifi_Rand_Core_Iv[7];

  for( i = 0; ; ) {
    ROUND( m_1 );

    // 7 rounds; check here because the number is odd.
    if( i + 1 >= 7 ) break;

    for( j = 0; j < 16; ++j ) {
      m_2[j] = m_1[Wifi_Rand_Core_Sigma[j]];
    }

    ROUND( m_2 );

    for( j = 0; j < 16; ++j ) {
      m_1[j] = m_2[Wifi_Rand_Core_Sigma[j]];
    }

    i += 2;
  }

  for( i = 0; i < 8; ++i ) {
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
  }
}

#undef G
#undef ROUND

void Wifi_Rand_Core_Update( Wifi_Rand_Core_State *S, const void *pin, size_t inlen )
{
  const unsigned char * in = (const unsigned char *)pin;
  if( inlen > 0 )
  {
    size_t left = S->buflen;
    size_t fill = WIFI_RAND_CORE_BLOCKBYTES - left;
    if( inlen > fill )
    {
      S->buflen = 0;
      memcpy( S->buf + left, in, fill ); /* Fill buffer */
      Wifi_Rand_Core_IncrementCounter( S, WIFI_RAND_CORE_BLOCKBYTES );
      Wifi_Rand_Core_Compress( S, S->buf ); /* Compress */
      in += fill; inlen -= fill;
      while(inlen > WIFI_RAND_CORE_BLOCKBYTES) {
        Wifi_Rand_Core_IncrementCounter(S, WIFI_RAND_CORE_BLOCKBYTES);
        Wifi_Rand_Core_Compress( S, in );
        in += WIFI_RAND_CORE_BLOCKBYTES;
        inlen -= WIFI_RAND_CORE_BLOCKBYTES;
      }
    }
    memcpy( S->buf + S->buflen, in, inlen );
    S->buflen += inlen;
  }
}

void Wifi_Rand_Core_Final( Wifi_Rand_Core_State *S, void *out, size_t outlen )
{
  assert( out != NULL);
  assert( outlen >= S->outlen );
  assert( !Wifi_Rand_Core_IsLastblock( S ) );

  Wifi_Rand_Core_IncrementCounter( S, ( uint32_t )S->buflen );
  Wifi_Rand_Core_SetLastblock( S );
  memset( S->buf + S->buflen, 0, WIFI_RAND_CORE_BLOCKBYTES - S->buflen ); /* Padding */
  Wifi_Rand_Core_Compress( S, S->buf );

  memcpy( out, S->h, outlen );
}
