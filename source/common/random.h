// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Antonio Niño Díaz

#ifndef DSWIFI_COMMON_RANDOM_H__
#define DSWIFI_COMMON_RANDOM_H__

#include <stdint.h>

// random.c assumes that Wifi_RandomAddEntropy is only called
// from ARM7, so enforce that that's the case by only
// declaring it there.
#ifdef ARM7
void Wifi_RandomAddEntropy(uint32_t value);
#endif

uint32_t Wifi_Random(void);

#endif // DSWIFI_COMMON_RANDOM_H__
