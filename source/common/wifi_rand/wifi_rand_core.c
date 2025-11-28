#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "wifi_rand.h"
#include "wifi_rand_impl.h"

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
  size_t i;
  memset( S, 0, sizeof( Wifi_Rand_Core_State ) );

  for( i = 0; i < 8; ++i ) S->h[i] = Wifi_Rand_Core_Iv[i];
}

/* init2 xors IV with input parameter block */
int Wifi_Rand_Core_InitParam( Wifi_Rand_Core_State *S, const Wifi_Rand_Core_Param *P )
{
  const unsigned char *p = ( const unsigned char * )( P );
  size_t i;

  Wifi_Rand_Core_Init0( S );

  /* IV XOR ParamBlock */
  for( i = 0; i < 8; ++i )
    S->h[i] ^= load32( &p[i * 4] );

  S->outlen = P->digest_length;
  return 0;
}


/* Sequential wifi_rand_core initialization */
int Wifi_Rand_Core_Init( Wifi_Rand_Core_State *S, size_t outlen )
{
  Wifi_Rand_Core_Param P[1];

  /* Move interval verification here? */
  if ( ( !outlen ) || ( outlen > WIFI_RAND_CORE_OUTBYTES ) ) return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length    = 0;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store32( &P->node_offset, 0 );
  store16( &P->xof_length, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  /* memset(P->reserved, 0, sizeof(P->reserved) ); */
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );
  return Wifi_Rand_Core_InitParam( S, P );
}

int Wifi_Rand_Core_InitKey( Wifi_Rand_Core_State *S, size_t outlen, const void *key, size_t keylen )
{
  Wifi_Rand_Core_Param P[1];

  if ( ( !outlen ) || ( outlen > WIFI_RAND_CORE_OUTBYTES ) ) return -1;

  if ( !key || !keylen || keylen > WIFI_RAND_CORE_KEYBYTES ) return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length    = (uint8_t)keylen;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store32( &P->node_offset, 0 );
  store16( &P->xof_length, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  /* memset(P->reserved, 0, sizeof(P->reserved) ); */
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );

  if( Wifi_Rand_Core_InitParam( S, P ) < 0 ) return -1;

  {
    uint8_t block[WIFI_RAND_CORE_BLOCKBYTES];
    memset( block, 0, WIFI_RAND_CORE_BLOCKBYTES );
    memcpy( block, key, keylen );
    Wifi_Rand_Core_Update( S, block, WIFI_RAND_CORE_BLOCKBYTES );
    secure_zero_memory( block, WIFI_RAND_CORE_BLOCKBYTES ); /* Burn the key from stack */
  }
  return 0;
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

int Wifi_Rand_Core_Update( Wifi_Rand_Core_State *S, const void *pin, size_t inlen )
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
  return 0;
}

int Wifi_Rand_Core_Final( Wifi_Rand_Core_State *S, void *out, size_t outlen )
{
  if( out == NULL || outlen < S->outlen )
    return -1;

  if( Wifi_Rand_Core_IsLastblock( S ) )
    return -1;

  Wifi_Rand_Core_IncrementCounter( S, ( uint32_t )S->buflen );
  Wifi_Rand_Core_SetLastblock( S );
  memset( S->buf + S->buflen, 0, WIFI_RAND_CORE_BLOCKBYTES - S->buflen ); /* Padding */
  Wifi_Rand_Core_Compress( S, S->buf );

  memcpy( out, S->h, outlen );
  return 0;
}
