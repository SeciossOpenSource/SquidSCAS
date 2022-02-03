/*
 *  Copyright (C) 2021 SECIOSS,INC.
 */
#include "secioss_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <magic.h>
#include <ctype.h>
#include <unistd.h>

#define MAGIC_HEADER_SIZE (16 * 1024)
#define HIGH_BUFF 4096
#define LOW_CHAR 32
#define LOW_BUFF 256

/* NUL-terminated version of strncpy() */
void xstrncpy(char * dest, const char * src, size_t n) {
    if ((src == NULL) || (strcmp(src, "") == 0))
        return;
    strncpy(dest, src, n - 1);
    dest[n - 1] = 0;
}

/* Emulate the Perl chomp() method: remove \r and \n from end of string */
void chomp(char * str) {
    size_t len = 0;

    if (str == NULL) return;
    len = strlen(str);
    if ((len > 0) && str[len - 1] == 10) {
        str[len - 1] = 0;
        len--;
    }
    if ((len > 0) && str[len - 1] == 13)
        str[len - 1] = 0;

    return;
}

/* Remove spaces and tabs from beginning and end of a string */
void trim(char * str) {
    int i = 0;
    int j = 0;

    /* Remove spaces and tabs from beginning */
    while ((str[i] == ' ') || (str[i] == '\t')) {
        i++;
    }
    if (i > 0) {
        for (j = i; j < strlen(str); j++) {
            str[j - i] = str[j];
        }
        str[j - i] = '\0';
    }

    /* Now remove spaces and tabs from end */
    i = strlen(str) - 1;
    while ((str[i] == ' ') || (str[i] == '\t')) {
        i--;
    }
    if (i < (strlen(str) - 1)) {
        str[i + 1] = '\0';
    }
}

size_t xstrnlen(const char *s, size_t n) {
    const char * p = (const char *)memchr(s, 0, n);
    return (p ? p - s : n);
}

int strcount(const char *str, char c)
{
    int count = 0;
    
    for (int i=0; str[i]!='\0'; i++) {
        if (str[i] == c) {
            count++;
        }
    }

    return count;
}

/* Try to emulate the Perl split() method: str is splitted on the
   all occurence of delim. Take care that empty fields are not returned */
char ** split(const char *str, char delim) {
    int max_size = strcount(str, delim) + 2; // 最大長 配列数＋ターミネート
    int str_length = strlen(str);
    char** buffer = malloc(sizeof(char*) * max_size + str_length + 1); // 文字列へのポインターの配列 ＋ 文字列実体
    if (!buffer) {
        return NULL;
    }

    char* str_buffer = (char *)(buffer + max_size);
    memset(buffer, 0, sizeof(char*) * max_size + str_length + 1);
    strcpy(str_buffer, str);

    int size = 0;
    char* start = str_buffer;
    for (int i=0; i<=str_length; i++) {
        if (str_buffer[i] == delim) {
            if (*start) {
                buffer[size] = start;
                size++;
            }
            str_buffer[i] = '\0';
            start = str_buffer + i + 1;
        } else if (str_buffer[i] == '\0') {
            buffer[size] = start;
            size++;
            buffer[size] = NULL;
        }
    }
    for (int i=0; buffer[i]; i++) {
        debugs(10, "DEBUG splited[%d] '%s'\n", i,  buffer[i]);
    }

    return buffer;
}

/* Return the length of a pointer array. Must be ended by NULL */
int ptrarray_length(char ** arr) {
    int i = 0;
    while (arr[i] != NULL) i++;
    return i;
}

void * xmallox(size_t len) {
    void * memres = malloc(len);
    if (memres == NULL) {
        fprintf(stderr, "Running Out of Memory!!!\n");
        exit(EXIT_FAILURE);
    }
    return memres;
}

/**
 * Searches all occurrences of old into s
 * and replaces with new
 */
char * replace(const char * s, const char * old, const char * new) {
    char * ret;
    int i, count = 0;
    size_t newlen = strlen(new);
    size_t oldlen = strlen(old);

    for (i = 0; s[i] != '\0'; i++) {
        if (strstr( & s[i], old) == & s[i]) {
            count++;
            i += oldlen - 1;
        }
    }
    ret = malloc(i + 1 + count * (newlen - oldlen));
    if (ret != NULL) {
        i = 0;
        while ( * s) {
            if (strstr(s, old) == s) {
                strcpy( & ret[i], new);
                i += newlen;
                s += oldlen;
            } else {
                ret[i++] = * s++;
            }
        }
        ret[i] = '\0';
    }

    return ret;
}

/**
 * returns file name extension
 */
const char * get_filename_ext(const char * filename) {
    const char * dot = strrchr(filename, '.');
    if (!dot || dot == filename)
        return "";
    return dot + 1;
}

/**
 * simple file copy
 */
int copy_file(int fd_src, const char * fname_dst) {
    char buf[HIGH_BUFF];
    ssize_t nread, total_read;
    int fd_dst;

    fd_dst = open(fname_dst, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd_dst < 0) {
        debugs(0, "DEBUG could not create [%s]\n", fname_dst);
        return -1;
    }

    total_read = 0;
    while (nread = read(fd_src, buf, sizeof(buf)), nread > 0) {
        total_read += nread;
        debugs(3, "DEBUG read [%d] bytes of data\n", (int) nread);
        char * out_ptr = buf;
        ssize_t written;
        do {
            written = write(fd_dst, out_ptr, nread);
            if (written >= 0) {
                nread -= written;
                out_ptr += written;
                debugs(3, "DEBUG %d bytes written\n", (int) written);
            } else {
                debugs(3, "DEBUG write error %d\n", (int) written);
            }
        } while (nread > 0);
    }

    debugs(3, "DEBUG closing %s (%d bytes)\n", fname_dst, (int) total_read);
    close(fd_dst);
    return 0;
}

/**
 * check for invalid chars in string
 */
int has_invalid_chars(const char * inv_chars, const char * target) {
    const char * c = target;
    debugs(10, "DEBUG checking for troublesome chars [%s] in [%s]\n", inv_chars, target);
    while ( * c) {
        if (strchr(inv_chars, * c)) {
            debugs(3, "WARNING found troublesome char [%c] in [%s]\n", * c, target);
            return 1;
        }
        c++;
    }
    debugs(3, "DEBUG no troublesome chars in [%s]\n", target);
    return 0;
}

int isIpAddress(char * src_addr) {
    int address;
    int i;

    /* make sure we have numbers and dots only! */
    if (strspn(src_addr, "0123456789.") != strlen(src_addr)) {
        return 1;
    }

    /* split up each number from string */
    char **s = split(src_addr, '.');
    if (!s[0]) {
        free(s);
        return 1;
    }
    address = atoi(s[0]);
    if (address < 0 || address > 255) {
        free(s);
        return 1;
    }

    for (i = 1; i <= 3; i++) {
        if (!s[i]) {
            free(s);
            return 1;
        }
        address = atoi(s[i]);
        if (address < 0 || address > 255) {
            free(s);
            return 1;
        }
    }
    free(s);

    return 0;
}

/* return 0 if path exists, -1 otherwise */
int isPathExists(const char * path) {
    struct stat sb;

    if ((path == NULL) || (strcmp(path, "") == 0)) return -1;

    if (lstat(path, & sb) != 0) {
        return -1;
    }

    return 0;
}

/* return 0 if path is secure, -1 otherwise */
int isPathSecure(const char * path) {
    struct stat sb;

    /* no path => unreal, that's possible ! */
    if (path == NULL) return -1;

    /* file doesn't exist or access denied = secure */
    /* fopen will fail */
    if (lstat(path, & sb) != 0) return 0;

    /* File is not a regular file => unsecure */
    if (S_ISLNK(sb.st_mode)) return -1;
    if (S_ISDIR(sb.st_mode)) return -1;
    if (S_ISCHR(sb.st_mode)) return -1;
    if (S_ISBLK(sb.st_mode)) return -1;
    if (S_ISFIFO(sb.st_mode)) return -1;
    if (S_ISSOCK(sb.st_mode)) return -1;

    return 0;
}

/* return 0 if file exists and is readable, -1 otherwise */
int isFileExists(const char * path) {
    struct stat sb;

    /* no path => unreal, that's possible ! */
    if (path == NULL) return S_ERROR;

    /* file doesn't exist or access denied */
    if (lstat(path, & sb) != 0) return S_ERROR;

    /* File is not a regular file */
    if (S_ISDIR(sb.st_mode)) return S_ERROR;
    if (S_ISCHR(sb.st_mode)) return S_ERROR;
    if (S_ISBLK(sb.st_mode)) return S_ERROR;
    if (S_ISFIFO(sb.st_mode)) return S_ERROR;
    if (S_ISSOCK(sb.st_mode)) return S_ERROR;

    return S_OK;
}

int mimetype(int fd_src, char * mime) {
    magic_t magic;
    char buf[MAGIC_HEADER_SIZE];
    ssize_t nread;
    const char * str = NULL;

    if ((magic = magic_open(MAGIC_MIME)) == NULL) {
        return 1;
    }

    if (magic_load(magic, NULL) == 0) {
        nread = read(fd_src, buf, sizeof(buf));
        if (nread > 0) {
            str = magic_buffer(magic, buf, nread);
            strncpy(mime, str, LOW_BUFF);
        }
        magic_close(magic);
        return 0;
    } else {
        magic_close(magic);
        return 1;
    }
}

char * tolowerstring(char * str) {
    int i = 0;
    while (str[i] != '\0') {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] = tolower((unsigned char) str[i]);
        }
        i++;
    }
    return str;
}

int sha1sum(int fd_src, char * checksum) {
    char buf[HIGH_BUFF];
    SHA_CTX sha1;
    unsigned char digest[20];

    SHA1_Init( & sha1);
    while (read(fd_src, buf, sizeof(buf)) > 0) {
        SHA1_Update( & sha1, (const unsigned char * ) buf, sizeof(buf));
    }
    SHA1_Final(digest, & sha1);

    sprintf(checksum, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
        digest[0], digest[1], digest[2], digest[3],
        digest[4], digest[5], digest[6], digest[7],
        digest[8], digest[9], digest[10], digest[11],
        digest[12], digest[13], digest[14], digest[15],
        digest[16], digest[17], digest[18], digest[19]);

    tolowerstring(checksum);

    return 0;
}

int urldecode(const char * s, char * dec, size_t n) {
    char * o;
    const char * end = s + strlen(s);
    int c;

    for (o = dec; s<=end && o<dec+n; o++) {
        c = * s++;
        if (c == '+') c = ' ';
        else if (c == '%' && (!ishex( * s++) ||
                !ishex( * s++) ||
                !sscanf(s - 2, "%2x", & c)))
            return -1;

        if (dec) * o = c;
    }
    dec[n] = '\0';

    return o - dec;
}
