#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "wifi_rand.h"
#include "wifi_rand_impl.h"

int Wifi_Rand_Init( Wifi_Rand_State *S ) {
  return Wifi_Rand_InitKey(S, NULL, 0);
}

int Wifi_Rand_InitKey( Wifi_Rand_State *S, const void *key, size_t keylen )
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

  if( Wifi_Rand_Core_InitParam( S->S, S->P ) < 0 ) {
    return -1;
  }

  if (keylen > 0) {
    uint8_t block[WIFI_RAND_CORE_BLOCKBYTES];
    memset(block, 0, WIFI_RAND_CORE_BLOCKBYTES);
    memcpy(block, key, keylen);
    Wifi_Rand_Core_Update(S->S, block, WIFI_RAND_CORE_BLOCKBYTES);
    secure_zero_memory(block, WIFI_RAND_CORE_BLOCKBYTES);
  }
  return 0;
}

int Wifi_Rand_Update( Wifi_Rand_State *S, const void *in, size_t inlen ) {
  return Wifi_Rand_Core_Update( S->S, in, inlen );
}

int Wifi_Rand_Finish(Wifi_Rand_State *S, Wifi_Rand_FinishedState *F) {
  /* Finalize the root hash */
  Wifi_Rand_Core_State C[1];
  memcpy(C, S->S, sizeof(C));
  if (Wifi_Rand_Core_Final(C, F->root, WIFI_RAND_CORE_OUTBYTES) < 0) {
    return -1;
  }

  /* Set common block structure values */
  /* Copy values from parent instance, and only change the ones below */
  Wifi_Rand_Core_Param *P = F->P;
  memcpy(P, S->P, sizeof(Wifi_Rand_Core_Param));
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

static int Wifi_Rand_FinishedReadBlock(Wifi_Rand_FinishedState *F, uint8_t out[WIFI_RAND_CORE_OUTBYTES]) {
  Wifi_Rand_Core_State C[1];
  Wifi_Rand_Core_Param *P = F->P;

  const uint32_t node_offset = load32(&P->node_offset);

  /* Initialize state */
  P->digest_length = WIFI_RAND_CORE_OUTBYTES;
  Wifi_Rand_Core_InitParam(C, P);
  /* Process key if needed */
  Wifi_Rand_Core_Update(C, F->root, WIFI_RAND_CORE_OUTBYTES);
  if (Wifi_Rand_Core_Final(C, out, WIFI_RAND_CORE_OUTBYTES) < 0) {
    return -1;
  }
  store32(&P->node_offset, node_offset + 1);

  return 0;
}

int Wifi_Rand_FinishedReadBytes(Wifi_Rand_FinishedState *F, void *outv, size_t outlen) {
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
    if (Wifi_Rand_FinishedReadBlock(F, out) < 0) {
      return -1;
    }
    out += WIFI_RAND_CORE_OUTBYTES;
    outlen -= WIFI_RAND_CORE_OUTBYTES;
  }

  if (Wifi_Rand_FinishedReadBlock(F, F->buf) < 0) {
    return -1;
  }

  memcpy(out, F->buf, outlen);
  F->buflen = WIFI_RAND_CORE_OUTBYTES - outlen;

  return 0;
}
