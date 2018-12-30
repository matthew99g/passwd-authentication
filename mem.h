#ifndef _MEM__
#define _MEM__
 
#include "vars.h"

#ifndef LARGE
#define SIZE 64
#else
#define SIZE 128
#endif

void organizeStack() {
    // pop Freed Memory off of Stack
    // < Wait for State to Equal SIZE Just as a Precaution >
    uint8_t state = 0x0;
    uint8_t saveState = 0x0;
    do {
        for(uint8_t i = saveState; i < SIZE; i++) {
            if(bAddressList[i + 1] && !bAddressList[i]) {
                state = 0x0;
                bAddressList[i] = bAddressList[i + 1];
                bAddressList[i + 1] = 0;

                saveState = i - 1;
                break;
            } else {
                state++;
                if(state >= SIZE)
                    break;
            }
        }
    } while(state < SIZE);
}

// Error Check Malloc
void *ecMalloc(unsigned int mem) {
    void *ptr = malloc(mem);
    if(!ptr) {
        fprintf(stderr, "Failed to Allocate Memory\n");
        exit(1);
    }

    return ptr;
}

// Check if data is empty
uint8_t checkEmptyPtr(void *ptr) {
    if(ptr == 0x0 || *(u_int8_t *)ptr == 0x0) {
        return 1;
    }

    return 0;
}

// Write Memory To Heap and Store Address
void *writeMemoryHeap(unsigned int uMem) {
    void *ptr = ecMalloc(uMem);

    bAddressList[bSave] = ptr;

    bSave++;
    return ptr;
}

// Free Remaining Memory
void freeMemoryHeap() {
    for(uint8_t i = 0; i < bSave; i++) {
        free(bAddressList[i]);
    }
}

// Free Specific Memory and pop Address off of Save Stack
void freeMemoryHeapP(void *ptr) {
    // Free Memory
    for(uint8_t i = 0; i < SIZE; i++) {
        if(bAddressList[i] == ptr) {
            free(bAddressList[i]);

            bSave--;

            bAddressList[i] = 0x0;
            break;
        } else if (!bAddressList[i])
            break;
    }

    organizeStack();
}

#endif