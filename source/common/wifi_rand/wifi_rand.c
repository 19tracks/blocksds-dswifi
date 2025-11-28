#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "wifi_rand.h"

void Wifi_Rand_Init( Wifi_Rand_State *S ) {
  Wifi_Rand_Core_InitCounter( S, 0 );
}

void Wifi_Rand_Finish(Wifi_Rand_State *S, Wifi_Rand_FinishedState *F) {
  /* Finalize the root hash */
  Wifi_Rand_State C[1];
  memcpy(C, S, sizeof(C));
  Wifi_Rand_Core_Final(C, F->root, WIFI_RAND_CORE_OUTBYTES);
  F->buflen = 0;
  F->counter = 0;
}

static void Wifi_Rand_FinishedReadBlock(Wifi_Rand_FinishedState *F, uint8_t out[WIFI_RAND_CORE_OUTBYTES]) {
  Wifi_Rand_State C[1];

  /* Initialize state */
  // pre-increment so we never use 0, as that's the counter we
  // use pre-finalization
  Wifi_Rand_Core_InitCounter(C, ++F->counter);
  /* Process key if needed */
  Wifi_Rand_Core_Update(C, F->root, WIFI_RAND_CORE_OUTBYTES);
  Wifi_Rand_Core_Final(C, out, WIFI_RAND_CORE_OUTBYTES);
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
  if (outlen % WIFI_RAND_CORE_OUTBYTES > 0) {
    if (outlen <= F->buflen) {
      memcpy(out, &F->buf[WIFI_RAND_CORE_OUTBYTES - F->buflen], outlen);
      F->buflen -= outlen;
      return;
    }

    memcpy(out, &F->buf[WIFI_RAND_CORE_OUTBYTES - F->buflen], F->buflen);
    out += F->buflen;
    outlen -= F->buflen;
    F->buflen = 0;
  }

  while (outlen >= WIFI_RAND_CORE_OUTBYTES) {
    Wifi_Rand_FinishedReadBlock(F, out);
    out += WIFI_RAND_CORE_OUTBYTES;
    outlen -= WIFI_RAND_CORE_OUTBYTES;
  }

  if (outlen > 0) {
    Wifi_Rand_FinishedReadBlock(F, F->buf);
    memcpy(out, F->buf, outlen);
    F->buflen = WIFI_RAND_CORE_OUTBYTES - outlen;
  }
}
