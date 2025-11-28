#ifndef DSWIFI_COMMON_WIFI_RAND_WIFI_RAND_H__
#define DSWIFI_COMMON_WIFI_RAND_WIFI_RAND_H__

#include <stddef.h>
#include <stdint.h>

  enum Wifi_Rand_Constant
  {
    WIFI_RAND_BLOCKBYTES = 64,
    WIFI_RAND_OUTBYTES   = 32,
  };

  typedef struct Wifi_Rand_State__
  {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[WIFI_RAND_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  } Wifi_Rand_State;

  /*
     ->S->S->buflen still stores the number of bytes in the
     buffer, but those bytes end at buf[WIFI_RAND_OUTBYTES]
     instead of starting at buf[0].
  */
  typedef struct Wifi_Rand_FinishedState__
  {
    uint8_t  root[WIFI_RAND_OUTBYTES];
    uint8_t  buf[WIFI_RAND_OUTBYTES];
    size_t   buflen;
    uint32_t counter;
  } Wifi_Rand_FinishedState;

  /* Streaming API */
  void Wifi_Rand_Core_InitCounter( Wifi_Rand_State *S, const uint32_t counter );
  void Wifi_Rand_Core_Update( Wifi_Rand_State *S, const void *in, size_t inlen );
  void Wifi_Rand_Core_Final( Wifi_Rand_State *S, void *out, size_t outlen );

  /* Variable output length API */
  void Wifi_Rand_Init( Wifi_Rand_State *S );
  static inline void Wifi_Rand_Update( Wifi_Rand_State *S, const void *in, size_t inlen ) {
    Wifi_Rand_Core_Update( S, in, inlen );
  }
  void Wifi_Rand_Finish( Wifi_Rand_State *S, Wifi_Rand_FinishedState *F );
  void Wifi_Rand_FinishedReadBytes( Wifi_Rand_FinishedState *F, void *out, size_t outlen );

#endif
