#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "wifi_rand.h"
#include "wifi_rand_impl.h"

int wifi_rand_init( wifi_rand_state *S ) {
  return wifi_rand_init_key(S, NULL, 0);
}

int wifi_rand_init_key( wifi_rand_state *S, const void *key, size_t keylen )
{
  if (NULL != key && keylen > WIFI_RAND_CORE_KEYBYTES) {
    return -1;
  }

  if (NULL == key && keylen > 0) {
    return -1;
  }

  /* Initialize parameter block */
  S->P->digest_length = WIFI_RAND_CORE_OUTBYTES;
  S->P->key_length    = keylen;
  S->P->fanout        = 1;
  S->P->depth         = 1;
  store32( &S->P->leaf_length, 0 );
  store32( &S->P->node_offset, 0 );
  store16( &S->P->xof_length, 0xFFFFUL );
  S->P->node_depth    = 0;
  S->P->inner_length  = 0;
  memset( S->P->salt,     0, sizeof( S->P->salt ) );
  memset( S->P->personal, 0, sizeof( S->P->personal ) );

  if( wifi_rand_core_init_param( S->S, S->P ) < 0 ) {
    return -1;
  }

  if (keylen > 0) {
    uint8_t block[WIFI_RAND_CORE_BLOCKBYTES];
    memset(block, 0, WIFI_RAND_CORE_BLOCKBYTES);
    memcpy(block, key, keylen);
    wifi_rand_core_update(S->S, block, WIFI_RAND_CORE_BLOCKBYTES);
    secure_zero_memory(block, WIFI_RAND_CORE_BLOCKBYTES);
  }
  return 0;
}

int wifi_rand_update( wifi_rand_state *S, const void *in, size_t inlen ) {
  return wifi_rand_core_update( S->S, in, inlen );
}

int wifi_rand_finish(wifi_rand_state *S, wifi_rand_finished_state *F) {
  /* Finalize the root hash */
  wifi_rand_core_state C[1];
  memcpy(C, S->S, sizeof(C));
  if (wifi_rand_core_final(C, F->root, WIFI_RAND_CORE_OUTBYTES) < 0) {
    return -1;
  }

  /* Set common block structure values */
  /* Copy values from parent instance, and only change the ones below */
  wifi_rand_core_param *P = F->P;
  memcpy(P, S->P, sizeof(wifi_rand_core_param));
  P->key_length = 0;
  P->fanout = 0;
  P->depth = 0;
  store32(&P->leaf_length, WIFI_RAND_CORE_OUTBYTES);
  P->node_offset = 0;
  P->node_depth = 0;
  P->inner_length = WIFI_RAND_CORE_OUTBYTES;

  F->buflen = 0;

  return 0;
}

static int wifi_rand_finished_read_block(wifi_rand_finished_state *F, uint8_t out[WIFI_RAND_CORE_OUTBYTES]) {
  wifi_rand_core_state C[1];
  wifi_rand_core_param *P = F->P;

  const uint32_t node_offset = load32(&P->node_offset);

  /* Initialize state */
  P->digest_length = WIFI_RAND_CORE_OUTBYTES;
  wifi_rand_core_init_param(C, P);
  /* Process key if needed */
  wifi_rand_core_update(C, F->root, WIFI_RAND_CORE_OUTBYTES);
  if (wifi_rand_core_final(C, out, WIFI_RAND_CORE_OUTBYTES) < 0) {
    return -1;
  }
  store32(&P->node_offset, node_offset + 1);

  return 0;
}

int wifi_rand_finished_read_bytes(wifi_rand_finished_state *F, void *outv, size_t outlen) {
  uint8_t *out = outv;

  if (NULL == out || outlen == 0) {
    return -1;
  }

  if (outlen <= F->buflen) {
    memcpy(out, &F->buf[WIFI_RAND_CORE_OUTBYTES - F->buflen], outlen);
    F->buflen -= outlen;
    return 0;
  }

  memcpy(out, &F->buf[WIFI_RAND_CORE_OUTBYTES - F->buflen], F->buflen);
  out += F->buflen;
  outlen -= F->buflen;

  while (outlen >= WIFI_RAND_CORE_OUTBYTES) {
    if (wifi_rand_finished_read_block(F, out) < 0) {
      return -1;
    }
    out += WIFI_RAND_CORE_OUTBYTES;
    outlen -= WIFI_RAND_CORE_OUTBYTES;
  }

  if (wifi_rand_finished_read_block(F, F->buf) < 0) {
    return -1;
  }

  memcpy(out, F->buf, outlen);
  F->buflen = WIFI_RAND_CORE_OUTBYTES - outlen;

  return 0;
}

#if 0
int wifi_rand(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen)
{
  wifi_rand_state S[1];

  /* Verify parameters */
  if (NULL == in && inlen > 0)
    return -1;

  if (NULL == out)
    return -1;

  if (NULL == key && keylen > 0)
    return -1;

  if (keylen > WIFI_RAND_CORE_KEYBYTES)
    return -1;

  if (outlen == 0)
    return -1;

  /* Initialize the root block structure */
  if (wifi_rand_init_key(S, outlen, key, keylen) < 0) {
    return -1;
  }

  /* Absorb the input message */
  wifi_rand_update(S, in, inlen);

  /* Compute the root node of the tree and the final hash using the counter construction */
  return wifi_rand_final(S, out, outlen);
}
#endif

#if defined(WIFI_RAND_SELFTEST)
#include <string.h>
#include "wifi_rand-kat.h"
int main( void )
{
  uint8_t key[WIFI_RAND_CORE_KEYBYTES];
  uint8_t buf[WIFI_RAND_KAT_LENGTH];
  size_t i, step, outlen;

  for( i = 0; i < WIFI_RAND_CORE_KEYBYTES; ++i ) {
    key[i] = ( uint8_t )i;
  }

  for( i = 0; i < WIFI_RAND_KAT_LENGTH; ++i ) {
    buf[i] = ( uint8_t )i;
  }

  /* Testing length of outputs rather than inputs */
  /* (Test of input lengths mostly covered by wifi_rand_core tests) */

  /* Test simple API */
  for( outlen = 1; outlen <= WIFI_RAND_KAT_LENGTH; ++outlen )
  {
      uint8_t hash[WIFI_RAND_KAT_LENGTH] = {0};
      if( wifi_rand( hash, outlen, buf, WIFI_RAND_KAT_LENGTH, key, WIFI_RAND_CORE_KEYBYTES ) < 0 ) {
        goto fail;
      }

      if( 0 != memcmp( hash, wifi_rand_keyed_kat[outlen-1], outlen ) )
      {
        goto fail;
      }
  }

  /* Test streaming API */
  for(step = 1; step < WIFI_RAND_CORE_BLOCKBYTES; ++step) {
    for (outlen = 1; outlen <= WIFI_RAND_KAT_LENGTH; ++outlen) {
      uint8_t hash[WIFI_RAND_KAT_LENGTH];
      wifi_rand_state S;
      uint8_t * p = buf;
      size_t mlen = WIFI_RAND_KAT_LENGTH;
      int err = 0;

      if( (err = wifi_rand_init_key(&S, outlen, key, WIFI_RAND_CORE_KEYBYTES)) < 0 ) {
        goto fail;
      }

      while (mlen >= step) {
        if ( (err = wifi_rand_update(&S, p, step)) < 0 ) {
          goto fail;
        }
        mlen -= step;
        p += step;
      }
      if ( (err = wifi_rand_update(&S, p, mlen)) < 0) {
        goto fail;
      }
      if ( (err = wifi_rand_final(&S, hash, outlen)) < 0) {
        goto fail;
      }

      if (0 != memcmp(hash, wifi_rand_keyed_kat[outlen-1], outlen)) {
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
