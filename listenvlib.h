#ifndef __LIST_ENV_LIB
#define __LIST_ENV_LIB

#include "memlib.h"
#include "errlib.h"
#include "listenv.h"

static void
listEnv()
{
    char **ep;
    ep = environ;

    if(ep < (char **)0)
        outputError(TRUE, TRUE, "listEnv");

    for(ep = environ; *ep != NULL; ep++) {
        puts(*ep);
    }
}

char **
fillEnvPtr()
{
    return environ;
}

#endif