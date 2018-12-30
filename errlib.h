#ifndef __ERR_LIB__
#define __ERR_LIB__

#include "errlibvar.h"

// No flush
void NORETURN
_err_exit(const char *fmt, __STD_ARGS)
{
    va_list argList;

    fprintf(stderr, "Error: ");

    va_start(argList, fmt);
    vfprintf(stderr, fmt, argList);
    va_end(argList);

    terminate(FALSE);
}

void NORETURN
errnoExit(const char *fmt, __STD_ARGS)
{
    va_list argList;

    fflush(stdout);

    fprintf(stderr, "errno: %s | ", strerror(errno));

    va_start(argList, fmt);
    vfprintf(stderr, fmt, argList);
    va_end(argList);

    fflush(stderr);

    terminate(TRUE);
}


void NORETURN
usageErr(const char *format, __STD_ARGS) {
    va_list argList;

    // wait for stdout
    fflush(stdout);

    fprintf(stderr, "Usage: ");
    va_start(argList, format);
    vfprintf(stderr, format, argList);
    va_end(argList);

    fflush(stderr);
    terminate(TRUE);
}

void NORETURN
errExit(const char *format, __STD_ARGS)
{
    va_list argList;

    // wait for stdout
    fflush(stdout);

    fprintf(stderr, "Error: ");
    va_start(argList, format);
    vfprintf(stderr, format, argList);
    va_end(argList);

    fflush(stderr);
    terminate(TRUE);
}

void NORETURN
fatal(const char *fmt)
{
    // wait for stdout
    fflush(stdout);

    fprintf(stderr, "%s\n", fmt);
    
    fflush(stderr);
    terminate(TRUE);
}

static void NORETURN
outputError(Boolean useErr, Boolean flushStdout,
        const char *fmt, __STD_ARGS)
{
    va_list ap;
    char userMsg[_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(userMsg, _BUF_SIZE, fmt, ap);
    va_end(ap);

    if(useErr)
        errnoExit("%s\n", userMsg);
    else if(!flushStdout)
        _err_exit("%s", userMsg);
    else
        errExit("%s\n", userMsg);

    // not supposed to reach here
    terminate(FALSE);
}

static void NORETURN
terminate(Boolean useExit3)
{
    char *s;

    /* Dump core if EN_DUMPCORE environment variable is defined and
    is a nonempty string; otherwise call exit(3) or _exit(2),
    depending on the value of 'useExit3'. */

    s = getenv("EF_DUMPCORE");

    if (s != NULL && *s != '\0')
        abort();
    else if(useExit3)
        exit(EXIT_FAILURE);
    else
        _exit(EXIT_FAILURE);
}

void NORETURN
cmdLineError(const char *format, __STD_ARGS)
{
    fflush(stdout);

    va_list argList;

    fprintf(stderr, "Command-line usage error | ");

    va_start(argList, format);
    vfprintf(stderr, format, argList);
    va_end(argList);

    fflush(stderr);

    terminate(TRUE);
}

#endif
