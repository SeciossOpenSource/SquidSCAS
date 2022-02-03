#ifndef __SECIOSS_UTILS_H
#define __SECIOSS_UTILS_H

#include <string.h>

void xstrncpy(char * dest, const char * src, size_t n);
void chomp(char * str);
void trim(char * str);
size_t xstrnlen(const char * s, size_t n);
char ** split(const char *str, char delim);
int ptrarray_length(char ** arr);
void * xmallox(size_t len);
char * replace(const char * s, const char * old, const char * new);
const char * get_filename_ext(const char * filename);
int copy_file(int fd_src, const char * fname_dst);
int has_invalid_chars(const char * inv_chars, const char * target);
int isIpAddress(char * src_addr);
int isPathExists(const char * path);
int isPathSecure(const char * path);
int isFileExists(const char * path);
int mimetype(int fd_src, char * mime);
char * tolowerstring(char * str);
int sha1sum(int fd_src, char * checksum);
int urldecode(const char * s, char * dec, size_t n);

inline int ishex(int x) {
    return (x >= '0' && x <= '9') ||
        (x >= 'a' && x <= 'f') ||
        (x >= 'A' && x <= 'F');
}

#define S_OK 0
#define S_ERROR 1

#include <c_icap/debug.h>
#include <pthread.h>

#define debugs(LEVEL, ARGS...) \
    { \
        ci_debug_printf(LEVEL, "%s(%d) %s: ", __FILE__, __LINE__, __FUNCTION__); \
        ci_debug_printf(LEVEL, ARGS); \
    }

#endif /* __SECIOSS_UTILS_H */
