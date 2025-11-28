#ifndef DSWIFI_COMMON_WIFI_RAND_WIFI_RAND_H__
#define DSWIFI_COMMON_WIFI_RAND_WIFI_RAND_H__

#include <stddef.h>
#include <stdint.h>

  enum Wifi_Rand_Core_Constant
  {
    WIFI_RAND_CORE_BLOCKBYTES = 64,
    WIFI_RAND_CORE_OUTBYTES   = 32,
    WIFI_RAND_CORE_KEYBYTES   = 32,
    WIFI_RAND_CORE_SALTBYTES  = 8,
    WIFI_RAND_CORE_PERSONALBYTES = 8
  };

  typedef struct Wifi_Rand_Core_State__
  {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[WIFI_RAND_CORE_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  } Wifi_Rand_Core_State;

  typedef struct Wifi_Rand_Core_Param__
  {
    uint8_t  digest_length; /* 1 */
    uint8_t  key_length;    /* 2 */
    uint8_t  fanout;        /* 3 */
    uint8_t  depth;         /* 4 */
    uint32_t leaf_length;   /* 8 */
    uint32_t node_offset;   /* 12 */
    uint16_t xof_length;    /* 14 */
    uint8_t  node_depth;    /* 15 */
    uint8_t  inner_length;  /* 16 */
    /* uint8_t  reserved[0]; */
    uint8_t  salt[WIFI_RAND_CORE_SALTBYTES]; /* 24 */
    uint8_t  personal[WIFI_RAND_CORE_PERSONALBYTES];  /* 32 */
  } Wifi_Rand_Core_Param;

  typedef struct Wifi_Rand_State__
  {
    Wifi_Rand_Core_State S[1];
    Wifi_Rand_Core_Param P[1];
  } Wifi_Rand_State;

  /*
     ->S->S->buflen still stores the number of bytes in the
     buffer, but those bytes end at buf[WIFI_RAND_CORE_OUTBYTES]
     instead of starting at buf[0].
  */
  typedef struct Wifi_Rand_FinishedState__
  {
    Wifi_Rand_Core_Param P[1];
    uint8_t root[WIFI_RAND_CORE_OUTBYTES];
    uint8_t buf[WIFI_RAND_CORE_OUTBYTES];
    size_t  buflen;
  } Wifi_Rand_FinishedState;

  /* Padded structs result in a compile-time error */
  enum {
    WIFI_RAND_DUMMY_1 = 1/(int)(sizeof(Wifi_Rand_Core_Param) == WIFI_RAND_CORE_OUTBYTES)
  };

  /* Streaming API */
  void Wifi_Rand_Core_InitParam( Wifi_Rand_Core_State *S, const Wifi_Rand_Core_Param *P );
  void Wifi_Rand_Core_Update( Wifi_Rand_Core_State *S, const void *in, size_t inlen );
  void Wifi_Rand_Core_Final( Wifi_Rand_Core_State *S, void *out, size_t outlen );

  /* Variable output length API */
  void Wifi_Rand_Init( Wifi_Rand_State *S );
  static inline void Wifi_Rand_Update( Wifi_Rand_State *S, const void *in, size_t inlen ) {
    Wifi_Rand_Core_Update( S->S, in, inlen );
  }
  void Wifi_Rand_Finish( Wifi_Rand_State *S, Wifi_Rand_FinishedState *F );
  void Wifi_Rand_FinishedReadBytes( Wifi_Rand_FinishedState *F, void *out, size_t outlen );

#endif
