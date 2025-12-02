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
void Wifi_RandomAddEntropyBytes(const void *in, size_t inlen)
{
    // We want to be:
    // - IN a critical section: Between reading the old state of the hasher and
    //   writing the new state, so that no bytes of entropy are lost. While
    //   holding the spinlock, so that we don't deadlock.
    // - NOT in a critical section: Probably while running the compression
    //   function, but I haven't implemented this, as it makes things difficult,
    //   and I want to check how important it is to respond promptly to
    //   interrupts on the ARM7 first.
    // - HOLDING the spinlock: While writing to WifiData->entropyHasher.state.
    // - NOT holding the spinlock: While running the compression function, so
    //   that the ARM9 doesn't spin for too long in a critical section while
    //   waiting to acquire it. While not in a critical section, so that we
    //   don't deadlock.

    // As mentioned in the comment in random.h, we occasionally stay in this
    // critical section for almost 0.2 milliseconds, which is unfortunate.
    int oldIME = enterCriticalSection();

    asm volatile ("" : : : "memory");

    // It's okay to discard `volatile` with memory barriers in place.
    Wifi_Rand_Hasher *hasher = (Wifi_Rand_Hasher*)&WifiData->entropyHasher.hasher;
    bool hashIsSlow = !Wifi_Rand_WillHashBeFast(hasher, inlen);

    Wifi_Rand_Hasher tempHasher;
    Wifi_Rand_Hasher *workingHasher = hasher;

    // There isn't much point in holding the lock while running the compression
    // function. The ARM9 won't be able to make use of the entropy we've
    // received while we're still working on mixing it in, but that's only
    // natural. If we held the lock, the ARM9 could end up stuck in a critical
    // section for just as long as the ARM7, potentially missing hblanks.
    if (hashIsSlow)
    {
        memcpy(&tempHasher, hasher, sizeof(tempHasher));
        workingHasher = &tempHasher;
    }
    else
    {
        while (Spinlock_Acquire(WifiData->entropyHasher) != SPINLOCK_OK);
    }

    Wifi_Rand_Hash(workingHasher, in, inlen);

    if (hashIsSlow)
    {
        while (Spinlock_Acquire(WifiData->entropyHasher) != SPINLOCK_OK);

        memcpy(hasher, &tempHasher, sizeof(tempHasher));
    }

    asm volatile ("" : : : "memory");

    Spinlock_Release(WifiData->entropyHasher);

    leaveCriticalSection(oldIME);
}

void Wifi_RandomAddEntropy(uint32_t value)
{
    Wifi_RandomAddEntropyBytes(&value, sizeof(value));
}
#endif

void Wifi_RandomBytes(void *out, size_t outlen)
{
    // We want to be:
    // - IN a critical section:
    //     - While reading and writing rngHasher.
    //     - Between Wifi_Rand_WillGenerateBeFast and Wifi_Rand_Generate or
    //       Wifi_Rand_Reserve.
    //     - While holding the spinlock, so that we don't deadlock.
    // - NOT in a critical section: While running the compression function, so
    //   that we don't miss interrupts on the ARM9.
    // - HOLDING the spinlock: While reading from WifiData->entropyHasher.state
    //   on the ARM9.
    // - NOT holding the spinlock: While not in a critical section, so that we
    //   don't deadlock.

    // [ ] critical section   [ ] spinlock

#ifdef ARM7
    char cpuDistinctValue = '7';
    Wifi_Rand_Generator *rngHasher = (Wifi_Rand_Generator*)&WifiData->rngHasher7;
    volatile uint32_t *generatorInputCounter = &WifiData->rngHasher7.inputCounter;
#else
    char cpuDistinctValue = '9';
    Wifi_Rand_Generator *rngHasher = (Wifi_Rand_Generator*)&WifiData->rngHasher9;
    volatile uint32_t *generatorInputCounter = &WifiData->rngHasher9.inputCounter;
#endif

    volatile uint32_t *hasherInputCounter = &WifiData->entropyHasher.hasher.inputCounter;

    int oldIME = enterCriticalSection();
    // [x] critical section   [ ] spinlock

    if (*generatorInputCounter < *hasherInputCounter)
    {
        Wifi_Rand_Hasher entropyHasher;
        Wifi_Rand_Generator rngHasherTemp;

#ifdef ARM9
        while (Spinlock_Acquire(WifiData->entropyHasher) != SPINLOCK_OK);
#endif
        asm volatile ("" : : : "memory");
        // [x] critical section   [x] spinlock

        uint32_t previousGeneratorInputCounter = *generatorInputCounter;

        memcpy(
            &entropyHasher,
            (void*)&WifiData->entropyHasher.hasher,
            sizeof(entropyHasher)
        );

#ifdef ARM9
        Spinlock_Release(WifiData->entropyHasher);
#endif
        // [x] critical section   [ ] spinlock
        leaveCriticalSection(oldIME);
        // [ ] critical section   [ ] spinlock

        Wifi_Rand_Hash(&entropyHasher, &cpuDistinctValue, sizeof(cpuDistinctValue));
        Wifi_Rand_SpawnGenerator(&entropyHasher, &rngHasherTemp);

        oldIME = enterCriticalSection();
        asm volatile ("" : : : "memory");
        // [x] critical section   [ ] spinlock

        // If these don't match, we were interrupted, and rngHasher has already
        // been updated with data at least as fresh as ours.
        //
        // This assumption is sound because we have no preemptive multitasking;
        // we won't be interrupted by a task that started earlier than we did
        // and thus has less fresh data, only by an interrupt that might start
        // and finish a brand new call to this function before returning to us.
        if(*generatorInputCounter == previousGeneratorInputCounter)
        {
            memcpy(rngHasher, &rngHasherTemp, sizeof(rngHasherTemp));
        }
    }

    // [x] critical section   [ ] spinlock

    if (Wifi_Rand_WillGenerateBeFast(rngHasher, outlen))
    {
        Wifi_Rand_Generate(rngHasher, out, outlen);
    }
    else
    {
        Wifi_Rand_Generator reservation;
        Wifi_Rand_Reserve(rngHasher, &reservation, outlen);

        leaveCriticalSection(oldIME);
        // [ ] critical section   [ ] spinlock

        Wifi_Rand_Generate(&reservation, out, outlen);

        oldIME = enterCriticalSection();
        // [x] critical section   [ ] spinlock

        Wifi_Rand_ReabsorbReservation(rngHasher, &reservation);
    }

    leaveCriticalSection(oldIME);
    // [ ] critical section   [ ] spinlock
}

uint32_t Wifi_Random(void)
{
    uint32_t x;
    Wifi_RandomBytes(&x, sizeof(x));
    return x;
}
