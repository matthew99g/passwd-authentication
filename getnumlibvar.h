#ifndef __GET_NUM_LIB_VAR
#define __GET_NUM_LIB_VAR

#include "errlib.h"

#define GN_NONNEG   01
#define GN_GT_O     02

#define GN_ANY_BASE 0100
#define GN_BASE_8   0200
#define GN_BASE_16  0400

long 
getLong(const char *arg, int flags, const char *name);

int
getInt(const char *arg, int flags, const char*name);

long
getNum(const char *fname, const char *arg,
        int flags, const char *name);

static void NORETURN
gnFail(const char *fname, const char *msg,
        const char *arg, const char *name);

#endif