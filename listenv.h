#ifndef __LIST_ENV
#define __LIST_ENV

extern char **environ;

static void
listEnv();

char **
fillEnvPtr();

#endif