#ifndef _VARS__
#define _VARS__

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <link.h>

void *bAddressList[64];
uint8_t bSave = 0;

#endif