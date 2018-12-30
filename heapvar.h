#ifndef _HEAP_VAR__
#define _HEAP_VAR__

#include "mem.h"

typedef struct __heap_int {
    int iValue;
    uint8_t *uiAddress;
    uint8_t *usAddress;
} HEAP_INT, *PHEAP_INT; 

PHEAP_INT hINTInit(int iValue) {
    PHEAP_INT hInt = (PHEAP_INT)writeMemoryHeap(1);
    
    if(!hInt) {
        fprintf(stderr, "Failed to Allocate Memory\n");
        freeMemoryHeap();
        exit(1);
    } else {
        hInt->iValue = iValue;
        hInt->uiAddress = (uint8_t *)&hInt->iValue;
        hInt->usAddress = (uint8_t *)hInt;
    }

    return hInt;
}

void freeHINT(PHEAP_INT phInt) {
    freeMemoryHeapP(phInt);
}

typedef struct __heap_string {
    char iValue[64];
    uint8_t *uiAddress;
    uint8_t *usAddress;
} HEAP_STRING, *PHEAP_STRING;

PHEAP_STRING hStringInit(const char *iValue) {
    PHEAP_STRING hString = (PHEAP_STRING)writeMemoryHeap(1);
    
    if(!hString) {
        fprintf(stderr, "Failed to Allocate Memory\n");
        freeMemoryHeap();
        exit(1);
    } else {
        if(iValue != 0) {
            strcpy(hString->iValue, iValue);
        }

        hString->uiAddress = (uint8_t *)&hString->iValue;
        hString->usAddress = (uint8_t *)hString;
    }

    return hString;
}

void freeHString(PHEAP_STRING phString) {
    freeMemoryHeapP(phString);
}

#endif