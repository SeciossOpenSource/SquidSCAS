#ifndef __SRV_CLAMAV_H
#define __SRV_CLAMAV_H

#include <sys/types.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <libgen.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sysexits.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "txt_format.h"

/* squidscas.h */
/*************  Default configuration file location  ***********/
#define CONFIG_FILE "squidscas.conf"

/************* Proxy configuration *************/
#define PROXY_SERVER "127.0.0.1"
#define PROXY_PORT "3128"


/************* Default Clamd configuration *************/
#define CLAMD_SERVER "127.0.0.1" 
#define CLAMD_PORT "3310" 
#define SCAN_ALL 1
#define SCAN_NONE 2

# ifdef S_SPLINT_S
extern char *strdup (char *s) /*@*/ ;
#endif

#include <stdarg.h>
#include <sys/types.h>
#include <regex.h>
#define LOW_CHAR 32
#define SMALL_CHAR 128
#define LOW_BUFF 256
#define SMALL_BUFF 1024
#define MEDIUM_BUFF 2048
#define HIGH_BUFF 4096
#define MAX_URL  8192
#define MAX_LOGIN_SZ 128
#define LBUFSIZ 32768
#define MAX_METHOD_SIZE  16



struct IN_BUFF {
    char url[MAX_URL];
    char src_address[1050];
    char ident[MAX_LOGIN_SZ];
    char method[LOW_CHAR];
    char ipaddress[16];
    char fqdn[1024];
};

#define TRUSTUSER      1
#define TRUSTCLIENT    2
#define ABORT          3
#define ABORTCONTENT   4
#define SCAN           5
#define SCANCONTENT    6
#define UNTRUSTUSER    7
#define UNTRUSTCLIENT  8

#define INVALID_CHARS "\\/:*?<>|"
#define PREFIX_SCAN "scan_"

#define max(a,b) \
    ({ __typeof__ (a) _a = (a); \
        __typeof__ (b) _b = (b); \
        _a > _b ? _a : _b; })

#define ACCEL_NORMAL 1
#define ACCEL_START  2
#define ACCEL_END    3

#define PATTERN_ARR_SIZE 32	/* Array of 32 patterns */

struct IP {
    short first;
    short second;
    short third;
};

int add_pattern(char *s, int level);
void regcomp_pattern(void);
int load_in_buff(char *);
int simple_pattern_compare(const char *, const int );
int client_pattern_compare(const char *, char *);
int load_patterns(void);
int readFileContent(char *filepath, char *kind);


// compatibility with folks that don't have __FUNCTION__, e.g. solaris
#if defined(__SUNPRO_CC) && !defined(__FUNCTION__)
    #ifdef __func__
        #define __FUNCTION__ __func__
    #else
        #define __FUNCTION__ ""
    #endif
#endif

#endif /* LOG_URL_SIZE */
