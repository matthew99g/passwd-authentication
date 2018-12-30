#define _DEFAULT_SOURCE
#define _X_OPEN_SOURCE

// gcc main.c -lcrypt -Wall -o password

#include "memlib.h"
#include "errlib.h"

#include <limits.h>
#include <pwd.h>
#include <shadow.h>

int
main(const int argc, const char *argv[])
{
    char *username, *password, *encrpyted, *p;
    struct passwd *pwd;
    struct spwd *spwd;
    Boolean authOk;
    ssize_t len;
    long lnmax;

    lnmax = sysconf(_SC_LOGIN_NAME_MAX);
    if (lnmax == -1)
        lnmax = 256;

    username = (char *)writeMemoryHeap(lnmax);
    if (username == NULL)
        errnoExit("writeMemoryHeap\n");

    printf("Username: ");
    fflush(stdout);
    if (fgets(username, lnmax, stdin) == NULL)
        fatal("Invalid Input");

    len = strlen(username);
    if (username[len -1] == '\n')
        username[len -1] = '\0';

    pwd = getpwnam(username);
    if (pwd == NULL)
        fatal("Couldn't get password record");
    spwd = getspnam(username);
    if (pwd == NULL && errno == EACCES)
        fatal("No permission to read shadow password file");

    freeMemoryHeapP(username);

    if(spwd != NULL)
        pwd->pw_passwd = spwd->sp_pwdp;

    password = getpass("Password: ");

    encrpyted = crypt(password, pwd->pw_passwd);
    for (p = password; *p != '\0'; )
        *++p = '\0';

    if(encrpyted == NULL)
        errnoExit("crypt, are you root?\n");

    authOk = strcmp(encrpyted, pwd->pw_passwd) == 0;
    if(!authOk) 
        fatal("Incorrect Password");

    printf("Successfully Authenticated: UID=%ld\n", (long) pwd->pw_uid);

    freeMemoryHeap();
    return EXIT_SUCCESS;
}