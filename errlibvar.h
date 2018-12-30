#ifndef __ERR_LIB_VAR
#define __ERR_LIB_VAR

#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <elf.h>

//#define MAX_ENAME 132

#define __STD_ARGS ...

#ifndef BUF_SIZE
#define BUF_SIZE 1024
#endif

#ifdef __GNUC__
#define NORETURN __attribute__ ((__noreturn__))
#else
#define NORETURN
#endif

#define __STD_ARGS ...
#define Boolean uint8_t

#ifndef NULL
#define NULL 0
#endif

#ifndef TRUE
#define TRUE 0x1
#endif

#ifndef FALSE 
#define FALSE 0x0
#endif

#ifdef __GNUC__
#define NORETURN __attribute__ ((__noreturn__))
#else
#define NORETURN
#endif

#ifndef _BUF_SIZE
#define _BUF_SIZE 512
#endif

void NORETURN
_err_exit(const char *fmt, __STD_ARGS);

static void NORETURN
terminate(Boolean useExit3);

void NORETURN
errnoExit(const char *fmt, __STD_ARGS);

void NORETURN
usageErr(const char *format, __STD_ARGS);

void NORETURN
errExit(const char *format, __STD_ARGS);

void NORETURN
fatal(const char *fmt);

static void NORETURN
outputError(Boolean useErr, Boolean flushStdout,
        const char *fmt, __STD_ARGS);

#endif