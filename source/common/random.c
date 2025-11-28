// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Antonio Niño Díaz

#include <string.h>
#include <time.h>

#include <dswifi_common.h>

#include "common/wifi_rand.h"
#include "common/spinlock.h"

#ifdef ARM7
#include "arm7/ipc.h"
#else
#include "arm9/ipc.h"
#endif

#ifdef ARM7
void Wifi_RandomAddEntropy(uint32_t value)
{
    // As mentioned in the comment in random.h, we occasionally stay in this
    // critical section for almost 0.2 milliseconds, which is unfortunate.
    int oldIME = enterCriticalSection();
    while (Spinlock_Acquire(WifiData->entropyHasher) != SPINLOCK_OK);

    asm volatile ("" : : : "memory");

    Wifi_Rand_Update(
        // It's okay to discard `volatile` with memory barriers in place.
        (Wifi_Rand_State*)&WifiData->entropyHasher.state,
        &value,
        sizeof(value)
    );
    WifiData->entropyHasher.dirty7 = true;
    WifiData->entropyHasher.dirty9 = true;

    asm volatile ("" : : : "memory");

    Spinlock_Release(WifiData->entropyHasher);
    leaveCriticalSection(oldIME);
}
#endif

uint32_t Wifi_Random(void)
{
#ifdef ARM7
    char cpuDistinctValue = '7';
    volatile bool *dirty = &WifiData->entropyHasher.dirty7;
    Wifi_Rand_FinishedState *rngHasher = (Wifi_Rand_FinishedState*)&WifiData->rngHasher7;
#else
    char cpuDistinctValue = '9';
    volatile bool *dirty = &WifiData->entropyHasher.dirty9;
    Wifi_Rand_FinishedState *rngHasher = (Wifi_Rand_FinishedState*)&WifiData->rngHasher9;
#endif

    if (*dirty)
    {
        Wifi_Rand_State entropyHasher;

        // Since it can take almost 0.2 milliseconds for the ARM7 to release
        // this lock, the ARM9 may also end up spending that long in this
        // critical section waiting to acquire it.
        int oldIME = enterCriticalSection();
#ifdef ARM9
        while (Spinlock_Acquire(WifiData->entropyHasher) != SPINLOCK_OK);
#endif
        asm volatile ("" : : : "memory");
        if (*dirty)
        {
            memcpy(
                &entropyHasher,
                (void*)&WifiData->entropyHasher.state,
                sizeof(entropyHasher)
            );
#ifdef ARM9
            Spinlock_Release(WifiData->entropyHasher);
#endif
            Wifi_Rand_Update(&entropyHasher, &cpuDistinctValue, sizeof(cpuDistinctValue));
            Wifi_Rand_Finish(&entropyHasher, rngHasher);
            *dirty = false;
        }
#ifdef ARM9
        else
        {
            Spinlock_Release(WifiData->entropyHasher);
        }
#endif
        leaveCriticalSection(oldIME);
    }

    uint32_t x;
    Wifi_Rand_FinishedReadBytes(rngHasher, &x, sizeof(x));

    return x;
}
