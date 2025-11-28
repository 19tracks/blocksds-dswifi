// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Antonio Niño Díaz

#include <string.h>
#include <time.h>

#include <dswifi_common.h>

#include "blake2/blake2.h"
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

    blake2xs_update(
        // okay to discard `volatile` with memory barriers in place
        (blake2xs_state*)&WifiData->entropyHasher.state,
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
    blake2xs_finished_state *rngHasher = (blake2xs_finished_state*)&WifiData->rngHasher7;
#else
    char cpuDistinctValue = '9';
    volatile bool *dirty = &WifiData->entropyHasher.dirty9;
    blake2xs_finished_state *rngHasher = (blake2xs_finished_state*)&WifiData->rngHasher9;
#endif

    if(*dirty) {
        blake2xs_state entropyHasher;

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
            blake2xs_update(&entropyHasher, &cpuDistinctValue, sizeof(cpuDistinctValue));
            blake2xs_finish(&entropyHasher, rngHasher);
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
    blake2xs_finished_read_bytes(rngHasher, &x, sizeof(x));

    return x;
}
