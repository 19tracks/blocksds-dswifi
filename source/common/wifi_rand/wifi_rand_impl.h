#ifndef DSWIFI_COMMON_WIFI_RAND_WIFI_RAND_IMPL_H__
#define DSWIFI_COMMON_WIFI_RAND_WIFI_RAND_IMPL_H__

#include <stdint.h>
#include <string.h>

static inline uint16_t load16( const void *src )
{
  uint16_t w;
  memcpy(&w, src, sizeof w);
  return w;
}

static inline uint32_t load32( const void *src )
{
  uint32_t w;
  memcpy(&w, src, sizeof w);
  return w;
}

static inline void store16( void *dst, uint16_t w )
{
  memcpy(dst, &w, sizeof w);
}

static inline void store32( void *dst, uint32_t w )
{
  memcpy(dst, &w, sizeof w);
}

static inline uint32_t rotr32( const uint32_t w, const unsigned c )
{
  return ( w >> c ) | ( w << ( 32 - c ) );
}

/* prevents compiler optimizing out memset() */
static inline void secure_zero_memory(void *v, size_t n)
{
  static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
  memset_v(v, 0, n);
}

#endif
