#ifndef WIFI_RAND_H
#define WIFI_RAND_H

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#define WIFI_RAND_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define WIFI_RAND_PACKED(x) x __attribute__((packed))
#endif

#if defined(__cplusplus)
extern "C" {
#endif

  enum wifi_rand_core_constant
  {
    WIFI_RAND_CORE_BLOCKBYTES = 64,
    WIFI_RAND_CORE_OUTBYTES   = 32,
    WIFI_RAND_CORE_KEYBYTES   = 32,
    WIFI_RAND_CORE_SALTBYTES  = 8,
    WIFI_RAND_CORE_PERSONALBYTES = 8
  };

  typedef struct wifi_rand_core_state__
  {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[WIFI_RAND_CORE_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  } wifi_rand_core_state;


  WIFI_RAND_PACKED(struct wifi_rand_core_param__
  {
    uint8_t  digest_length; /* 1 */
    uint8_t  key_length;    /* 2 */
    uint8_t  fanout;        /* 3 */
    uint8_t  depth;         /* 4 */
    uint32_t leaf_length;   /* 8 */
    uint32_t node_offset;  /* 12 */
    uint16_t xof_length;    /* 14 */
    uint8_t  node_depth;    /* 15 */
    uint8_t  inner_length;  /* 16 */
    /* uint8_t  reserved[0]; */
    uint8_t  salt[WIFI_RAND_CORE_SALTBYTES]; /* 24 */
    uint8_t  personal[WIFI_RAND_CORE_PERSONALBYTES];  /* 32 */
  });

  typedef struct wifi_rand_core_param__ wifi_rand_core_param;

  typedef struct wifi_rand_state__
  {
    wifi_rand_core_state S[1];
    wifi_rand_core_param P[1];
  } wifi_rand_state;

  /*
     ->S->S->buflen still stores the number of bytes in the
     buffer, but those bytes end at buf[WIFI_RAND_CORE_OUTBYTES]
     instead of starting at buf[0].
  */
  typedef struct wifi_rand_finished_state__
  {
    wifi_rand_core_param P[1];
    uint8_t root[WIFI_RAND_CORE_OUTBYTES];
    uint8_t buf[WIFI_RAND_CORE_OUTBYTES];
    size_t  buflen;
  } wifi_rand_finished_state;

  /* Padded structs result in a compile-time error */
  enum {
    WIFI_RAND_DUMMY_1 = 1/(int)(sizeof(wifi_rand_core_param) == WIFI_RAND_CORE_OUTBYTES)
  };

  /* Streaming API */
  int wifi_rand_core_init( wifi_rand_core_state *S, size_t outlen );
  int wifi_rand_core_init_key( wifi_rand_core_state *S, size_t outlen, const void *key, size_t keylen );
  int wifi_rand_core_init_param( wifi_rand_core_state *S, const wifi_rand_core_param *P );
  int wifi_rand_core_update( wifi_rand_core_state *S, const void *in, size_t inlen );
  int wifi_rand_core_final( wifi_rand_core_state *S, void *out, size_t outlen );

  /* Variable output length API */
  int wifi_rand_init( wifi_rand_state *S );
  int wifi_rand_init_key( wifi_rand_state *S, const void *key, size_t keylen );
  int wifi_rand_update( wifi_rand_state *S, const void *in, size_t inlen );
  int wifi_rand_finish( wifi_rand_state *S, wifi_rand_finished_state *F );
  int wifi_rand_finished_read_bytes( wifi_rand_finished_state *F, void *out, size_t outlen );

  /* Simple API */
  int wifi_rand_core( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

  int wifi_rand( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

#if defined(__cplusplus)
}
#endif

#endif
