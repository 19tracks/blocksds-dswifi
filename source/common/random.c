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

    // It's okay to discard `volatile` with memory barriers in place.
    Wifi_Rand_State *state = (Wifi_Rand_State*)&WifiData->entropyHasher.state;
    bool compressTriggered = Wifi_Rand_WillUpdateTriggerCompress(state, sizeof(value));

    Wifi_Rand_State tempState;
    Wifi_Rand_State *workingState = state;

    // There isn't much point in holding the lock while running the compression
    // function. The ARM9 won't be able to make use of the entropy we've
    // received while we're still working on mixing it in, but that's only
    // natural. If we held the lock, the ARM9 could end up stuck in a critical
    // section for just as long as the ARM7, potentially missing hblanks.
    if (compressTriggered)
    {
        memcpy(&tempState, state, sizeof(tempState));
        workingState = &tempState;

        Spinlock_Release(WifiData->entropyHasher);
    }

    Wifi_Rand_Update(workingState, &value, sizeof(value));

    if (compressTriggered)
    {
        while (Spinlock_Acquire(WifiData->entropyHasher) != SPINLOCK_OK);

        memcpy(state, &tempState, sizeof(tempState));
    }

    asm volatile ("" : : : "memory");

    Spinlock_Release(WifiData->entropyHasher);
    leaveCriticalSection(oldIME);
}
#endif

uint32_t Wifi_Random(void)
{
#ifdef ARM7
    char cpuDistinctValue = '7';
    Wifi_Rand_FinishedState *rngHasher = (Wifi_Rand_FinishedState*)&WifiData->rngHasher7;
    volatile uint32_t *finishedInputCounter = &WifiData->rngHasher7.input_counter;
#else
    char cpuDistinctValue = '9';
    Wifi_Rand_FinishedState *rngHasher = (Wifi_Rand_FinishedState*)&WifiData->rngHasher9;
    volatile uint32_t *finishedInputCounter = &WifiData->rngHasher9.input_counter;
#endif

    volatile uint32_t *totalInputBytes = &WifiData->entropyHasher.state.input_counter;

    if (*finishedInputCounter < *totalInputBytes)
    {
        Wifi_Rand_State entropyHasher;
        Wifi_Rand_FinishedState rngHasherTemp;

        int oldIME = enterCriticalSection();
#ifdef ARM9
        while (Spinlock_Acquire(WifiData->entropyHasher) != SPINLOCK_OK);
#endif
        asm volatile ("" : : : "memory");

        uint32_t previousFinishedInputCounter = *finishedInputCounter;

        // This function might have been called again in an interrupt between
        // the earlier check and here, so don't do unnecessary work in that case
        if (*finishedInputCounter < *totalInputBytes)
        {
            memcpy(
                &entropyHasher,
                (void*)&WifiData->entropyHasher.state,
                sizeof(entropyHasher)
            );

#ifdef ARM9
            Spinlock_Release(WifiData->entropyHasher);
#endif
            leaveCriticalSection(oldIME);

            Wifi_Rand_Update(&entropyHasher, &cpuDistinctValue, sizeof(cpuDistinctValue));
            Wifi_Rand_Finish(&entropyHasher, &rngHasherTemp);

            oldIME = enterCriticalSection();
            asm volatile ("" : : : "memory");
            // If these don't match, we were interrupted, and rngHasher has
            // already been updated with data at least as fresh as ours.
            if(*finishedInputCounter == previousFinishedInputCounter)
            {
                memcpy(rngHasher, &rngHasherTemp, sizeof(rngHasherTemp));
            }
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
