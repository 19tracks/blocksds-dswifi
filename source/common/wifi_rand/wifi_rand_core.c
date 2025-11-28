#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "wifi_rand.h"
#include "wifi_rand_impl.h"

static const uint32_t wifi_rand_core_IV[8] =
{
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t wifi_rand_core_sigma[10][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
};

static void wifi_rand_core_set_lastnode( wifi_rand_core_state *S )
{
  S->f[1] = (uint32_t)-1;
}

/* Some helper functions, not necessarily useful */
static int wifi_rand_core_is_lastblock( const wifi_rand_core_state *S )
{
  return S->f[0] != 0;
}

static void wifi_rand_core_set_lastblock( wifi_rand_core_state *S )
{
  if( S->last_node ) wifi_rand_core_set_lastnode( S );

  S->f[0] = (uint32_t)-1;
}

static void wifi_rand_core_increment_counter( wifi_rand_core_state *S, const uint32_t inc )
{
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
}

static void wifi_rand_core_init0( wifi_rand_core_state *S )
{
  size_t i;
  memset( S, 0, sizeof( wifi_rand_core_state ) );

  for( i = 0; i < 8; ++i ) S->h[i] = wifi_rand_core_IV[i];
}

/* init2 xors IV with input parameter block */
int wifi_rand_core_init_param( wifi_rand_core_state *S, const wifi_rand_core_param *P )
{
  const unsigned char *p = ( const unsigned char * )( P );
  size_t i;

  wifi_rand_core_init0( S );

  /* IV XOR ParamBlock */
  for( i = 0; i < 8; ++i )
    S->h[i] ^= load32( &p[i * 4] );

  S->outlen = P->digest_length;
  return 0;
}


/* Sequential wifi_rand_core initialization */
int wifi_rand_core_init( wifi_rand_core_state *S, size_t outlen )
{
  wifi_rand_core_param P[1];

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
  return wifi_rand_core_init_param( S, P );
}

int wifi_rand_core_init_key( wifi_rand_core_state *S, size_t outlen, const void *key, size_t keylen )
{
  wifi_rand_core_param P[1];

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

  if( wifi_rand_core_init_param( S, P ) < 0 ) return -1;

  {
    uint8_t block[WIFI_RAND_CORE_BLOCKBYTES];
    memset( block, 0, WIFI_RAND_CORE_BLOCKBYTES );
    memcpy( block, key, keylen );
    wifi_rand_core_update( S, block, WIFI_RAND_CORE_BLOCKBYTES );
    secure_zero_memory( block, WIFI_RAND_CORE_BLOCKBYTES ); /* Burn the key from stack */
  }
  return 0;
}

#define G(r,i,a,b,c,d)                      \
  do {                                      \
    a = a + b + m[wifi_rand_core_sigma[r][2*i+0]]; \
    d = rotr32(d ^ a, 16);                  \
    c = c + d;                              \
    b = rotr32(b ^ c, 12);                  \
    a = a + b + m[wifi_rand_core_sigma[r][2*i+1]]; \
    d = rotr32(d ^ a, 8);                   \
    c = c + d;                              \
    b = rotr32(b ^ c, 7);                   \
  } while(0)

#define ROUND(r)                    \
  do {                              \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)

static void wifi_rand_core_compress( wifi_rand_core_state *S, const uint8_t in[WIFI_RAND_CORE_BLOCKBYTES] )
{
  uint32_t m[16];
  uint32_t v[16];
  size_t i;

  for( i = 0; i < 16; ++i ) {
    m[i] = load32( in + i * sizeof( m[i] ) );
  }

  for( i = 0; i < 8; ++i ) {
    v[i] = S->h[i];
  }

  v[ 8] = wifi_rand_core_IV[0];
  v[ 9] = wifi_rand_core_IV[1];
  v[10] = wifi_rand_core_IV[2];
  v[11] = wifi_rand_core_IV[3];
  v[12] = S->t[0] ^ wifi_rand_core_IV[4];
  v[13] = S->t[1] ^ wifi_rand_core_IV[5];
  v[14] = S->f[0] ^ wifi_rand_core_IV[6];
  v[15] = S->f[1] ^ wifi_rand_core_IV[7];

  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );

  for( i = 0; i < 8; ++i ) {
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
  }
}

#undef G
#undef ROUND

int wifi_rand_core_update( wifi_rand_core_state *S, const void *pin, size_t inlen )
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
      wifi_rand_core_increment_counter( S, WIFI_RAND_CORE_BLOCKBYTES );
      wifi_rand_core_compress( S, S->buf ); /* Compress */
      in += fill; inlen -= fill;
      while(inlen > WIFI_RAND_CORE_BLOCKBYTES) {
        wifi_rand_core_increment_counter(S, WIFI_RAND_CORE_BLOCKBYTES);
        wifi_rand_core_compress( S, in );
        in += WIFI_RAND_CORE_BLOCKBYTES;
        inlen -= WIFI_RAND_CORE_BLOCKBYTES;
      }
    }
    memcpy( S->buf + S->buflen, in, inlen );
    S->buflen += inlen;
  }
  return 0;
}

int wifi_rand_core_final( wifi_rand_core_state *S, void *out, size_t outlen )
{
  uint8_t buffer[WIFI_RAND_CORE_OUTBYTES] = {0};
  size_t i;

  if( out == NULL || outlen < S->outlen )
    return -1;

  if( wifi_rand_core_is_lastblock( S ) )
    return -1;

  wifi_rand_core_increment_counter( S, ( uint32_t )S->buflen );
  wifi_rand_core_set_lastblock( S );
  memset( S->buf + S->buflen, 0, WIFI_RAND_CORE_BLOCKBYTES - S->buflen ); /* Padding */
  wifi_rand_core_compress( S, S->buf );

  for( i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
    store32( buffer + sizeof( S->h[i] ) * i, S->h[i] );

  memcpy( out, buffer, outlen );
  secure_zero_memory(buffer, sizeof(buffer));
  return 0;
}

int wifi_rand_core( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen )
{
  wifi_rand_core_state S[1];

  /* Verify parameters */
  if ( NULL == in && inlen > 0 ) return -1;

  if ( NULL == out ) return -1;

  if ( NULL == key && keylen > 0) return -1;

  if( !outlen || outlen > WIFI_RAND_CORE_OUTBYTES ) return -1;

  if( keylen > WIFI_RAND_CORE_KEYBYTES ) return -1;

  if( keylen > 0 )
  {
    if( wifi_rand_core_init_key( S, outlen, key, keylen ) < 0 ) return -1;
  }
  else
  {
    if( wifi_rand_core_init( S, outlen ) < 0 ) return -1;
  }

  wifi_rand_core_update( S, ( const uint8_t * )in, inlen );
  wifi_rand_core_final( S, out, outlen );
  return 0;
}

#if defined(SUPERCOP)
int crypto_hash( unsigned char *out, unsigned char *in, unsigned long long inlen )
{
  return wifi_rand_core( out, WIFI_RAND_CORE_OUTBYTES, in, inlen, NULL, 0 );
}
#endif

#if defined(WIFI_RAND_CORE_SELFTEST)
#include <string.h>
#include "wifi_rand-kat.h"
int main( void )
{
  uint8_t key[WIFI_RAND_CORE_KEYBYTES];
  uint8_t buf[WIFI_RAND_KAT_LENGTH];
  size_t i, step;

  for( i = 0; i < WIFI_RAND_CORE_KEYBYTES; ++i )
    key[i] = ( uint8_t )i;

  for( i = 0; i < WIFI_RAND_KAT_LENGTH; ++i )
    buf[i] = ( uint8_t )i;

  /* Test simple API */
  for( i = 0; i < WIFI_RAND_KAT_LENGTH; ++i )
  {
    uint8_t hash[WIFI_RAND_CORE_OUTBYTES];
    wifi_rand_core( hash, WIFI_RAND_CORE_OUTBYTES, buf, i, key, WIFI_RAND_CORE_KEYBYTES );

    if( 0 != memcmp( hash, wifi_rand_core_keyed_kat[i], WIFI_RAND_CORE_OUTBYTES ) )
    {
      goto fail;
    }
  }

  /* Test streaming API */
  for(step = 1; step < WIFI_RAND_CORE_BLOCKBYTES; ++step) {
    for (i = 0; i < WIFI_RAND_KAT_LENGTH; ++i) {
      uint8_t hash[WIFI_RAND_CORE_OUTBYTES];
      wifi_rand_core_state S;
      uint8_t * p = buf;
      size_t mlen = i;
      int err = 0;

      if( (err = wifi_rand_core_init_key(&S, WIFI_RAND_CORE_OUTBYTES, key, WIFI_RAND_CORE_KEYBYTES)) < 0 ) {
        goto fail;
      }

      while (mlen >= step) {
        if ( (err = wifi_rand_core_update(&S, p, step)) < 0 ) {
          goto fail;
        }
        mlen -= step;
        p += step;
      }
      if ( (err = wifi_rand_core_update(&S, p, mlen)) < 0) {
        goto fail;
      }
      if ( (err = wifi_rand_core_final(&S, hash, WIFI_RAND_CORE_OUTBYTES)) < 0) {
        goto fail;
      }

      if (0 != memcmp(hash, wifi_rand_core_keyed_kat[i], WIFI_RAND_CORE_OUTBYTES)) {
        goto fail;
      }
    }
  }

  puts( "ok" );
  return 0;
fail:
  puts("error");
  return -1;
}
#endif
