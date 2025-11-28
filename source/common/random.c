// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Antonio Niño Díaz

#include <string.h>
#include <time.h>

#include <dswifi_common.h>

#include "wifi_rand/wifi_rand.h"
#include "common/spinlock.h"

#ifdef ARM7
#include "arm7/ipc.h"
#else
#include "arm9/ipc.h"
#endif

void Wifi_RandomAddEntropy(uint32_t value)
{
    int oldIME = enterCriticalSection();
    while (Spinlock_Acquire(WifiData->entropyHasher) != SPINLOCK_OK);

    asm volatile ("" : : : "memory");

    wifi_rand_update(
        // okay to discard `volatile` with memory barriers in place
        (wifi_rand_state*)&WifiData->entropyHasher.state,
        &value,
        sizeof(value)
    );
    WifiData->entropyHasher.dirty7 = true;
    WifiData->entropyHasher.dirty9 = true;

    asm volatile ("" : : : "memory");

    Spinlock_Release(WifiData->entropyHasher);
    leaveCriticalSection(oldIME);
}

uint32_t Wifi_Random(void)
{
#ifdef ARM7
    char cpuDistinctValue = '7';
    volatile bool *dirty = &WifiData->entropyHasher.dirty7;
    wifi_rand_finished_state *rngHasher = (wifi_rand_finished_state*)&WifiData->rngHasher7;
#else
    char cpuDistinctValue = '9';
    volatile bool *dirty = &WifiData->entropyHasher.dirty9;
    wifi_rand_finished_state *rngHasher = (wifi_rand_finished_state*)&WifiData->rngHasher9;
#endif

    if(*dirty) {
        wifi_rand_state entropyHasher;

        int oldIME = enterCriticalSection();
#ifdef ARM9
        while (Spinlock_Acquire(WifiData->entropyHasher) != SPINLOCK_OK);
#endif
        asm volatile ("" : : : "memory");
        if(*dirty) {
            memcpy(
                &entropyHasher,
                (void*)&WifiData->entropyHasher.state,
                sizeof(entropyHasher)
            );
#ifdef ARM9
            Spinlock_Release(WifiData->entropyHasher);
#endif
            wifi_rand_update(&entropyHasher, &cpuDistinctValue, sizeof(cpuDistinctValue));
            wifi_rand_finish(&entropyHasher, rngHasher);
            *dirty = false;
        }
#ifdef ARM9
        else {
            Spinlock_Release(WifiData->entropyHasher);
        }
#endif
        leaveCriticalSection(oldIME);
    }

    uint32_t x;
    wifi_rand_finished_read_bytes(rngHasher, &x, sizeof(x));

    return x;
}
