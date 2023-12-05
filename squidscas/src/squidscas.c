/*
 *  Copyright (C) 2020 Kaoru Sekiguchi
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 *  Some part of the code of squidscas are learn or simply copy/paste
 *  from the squidclamav c-icap service written by Gilles Darold.
 *
 *  Copyright (C) 2019 Gilles Darold
 *
 * Thanks to him for his great work.
 */

/*
 Fix conflicting types for `strnstr' on freeBSD
 between string.h and c_icap/util.h declaration
 */
#ifndef HAVE_STRNSTR
#define HAVE_STRNSTR 1
#endif

#include "c-icap.h"
#include "service.h"
#include "header.h"
#include "body.h"
#include "simple_api.h"
#include "debug.h"
#include "cfg_param.h"
#include "squidscas.h"
#include "filetype.h"
#include "ci_threads.h"
#include "mem.h"
#include "commands.h"
#include "txtTemplate.h"
#include <errno.h>
#include <signal.h>

/* SECIOSS */
#include "secioss_utils.h"
#include <libmemcached/memcached.h>
#include <openssl/sha.h>
#include <curl/curl.h>

#if defined(LIBMEMCACHED_VERSION_HEX)
#if LIBMEMCACHED_VERSION_HEX > 0x01000000
#include <libmemcached/util.h>
#else
#include <libmemcached/util/pool.h>
#endif /* LIBMEMCACHED_VERSION_HEX > 0x01000000*/
#else
/* And older version of libmemcached*/
#include <libmemcached/memcached_pool.h>
#endif

#define INIT_LIST_SIZE 128
#define LINE_READ_BUFF 1024
#define MC_DOMAINLEN 32
#define MC_MAXKEYLEN 250
#define HOSTNAME_LEN 256
#define ID_LEN 256
#define NUM_OF_URLS 10
#define MAX_DOMAIN 256
#define MAX_PARAM_LENGHT 1024
#define MAX_TOKEN 8192
typedef struct scas_service {
    char id[ID_LEN];
    char urls[NUM_OF_URLS][MAX_URL];;
    char login_url[MAX_URL];
    regex_t login_regexv;
    char update_urls[NUM_OF_URLS][MAX_URL];
    char update_params[NUM_OF_URLS][MAX_PARAM_LENGHT];
    int share;
    regex_t share_url;
    regex_t share_regexv;
} scas_service_t;

/* Structure used to store information passed throught the module methods */
typedef struct scas_req_data {
    ci_simple_file_t *body;
    ci_request_t *req;
    ci_membuf_t *error_page;
    const scas_service_t *service;
    int blocked;
    int no_more_scan;
    int virus;
    int code;
    char *url;
    char *user;
    char *clientip;
    char *operation;
    char *allowed;
    char *share_user;
} scas_req_data_t;

struct Buffer {
    char *data;
    int size;
};

static int SEND_PERCENT_BYTES = 0;
static ci_off_t START_SEND_AFTER = 1;

/*squidscas service extra data ... */
ci_service_xdata_t *squidscas_xdata = NULL;

int AVREQDATA_POOL = -1;

/* SECIOSS */

typedef struct mc_server {
    char hostname[HOSTNAME_LEN];
    int port;
} mc_server_t;

typedef struct scas_url {
    char url[MAX_URL];
} scas_url_t;

typedef struct scas_virus {
    char id[ID_LEN];
    char checksum[LOW_BUFF];
} scas_virus_t;

typedef struct {
    char pattern[LOW_BUFF];
    int type;
    int flag;
    regex_t regexv;
} SCPattern;

static ci_list_t *whitelist = NULL;
static ci_list_t *blacklist = NULL;
static ci_list_t *mamcache_servers_list = NULL;
static ci_list_t *services_list = NULL;
static ci_list_t *virus_list = NULL;
static char mail_export_path[PATH_MAX];

static pthread_mutex_t MUTEX = PTHREAD_MUTEX_INITIALIZER;
static memcached_st *MC = NULL;
static memcached_pool_st *MC_POOL = NULL;

int squidscas_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf);
int squidscas_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t * );
int squidscas_end_of_data_handler(ci_request_t * );
void *squidscas_init_request_data(ci_request_t *req);
void squidscas_close_service();
void squidscas_release_request_data(void *data);
int squidscas_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t *req);
int squidscas_post_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf);

/* General functions */
void set_istag(ci_service_xdata_t *srv_xdata);

/* SECIOSS */
ci_headers_list_t *get_headers_from_entities(ci_encaps_entity_t **entities, int type);
int mc_cfg_servers_set(const char **argv);
int scas_cfg_url_list_set(const char *filepath, ci_list_t **url_list);
int scas_cfg_services_set(const char *filepath);
int scas_cfg_virus_list_set(const char *filepath);
size_t authz_writer(char *ptr, size_t size, size_t nmemb, void *stream);
char *authorization(const char *action, const char *username, const char *clientip, const char *user_agent);

/* Declare SeciossCAS C-ICAP service */
CI_DECLARE_MOD_DATA ci_service_module_t service = {
    "squidscas",    /*Module name */
    "SeciossCAS/CASB service",    /* Module short description */
    ICAP_RESPMOD | ICAP_REQMOD,    /* Service type modification */
    squidscas_init_service,    /* init_service. */
    squidscas_post_init_service,    /* post_init_service. */
    squidscas_close_service,    /* close_service */
    squidscas_init_request_data,    /* init_request_data. */
    squidscas_release_request_data,    /* release request data */
    squidscas_check_preview_handler,    /* Preview data */
    squidscas_end_of_data_handler,    /* when all data has been received */
    squidscas_io,
    NULL,
    NULL
};

static int statit = 0;
static int timeout = 1;
static char redirect_url[MAX_URL];
static char authz_api[MAX_URL];
static char authz_api_token[MAX_TOKEN];
static SCPattern *patterns = NULL;
static int pattc = 0;
static int current_pattern_size = 0;
static ci_off_t maxsize = 0;
static int dnslookup = 1;
/* Default scan mode ScanAllExcept */
static int scan_mode = 1;
static char scan_path[PATH_MAX];

/* --------------- URL CHECK --------------------------- */

struct http_info {
    char method[MAX_METHOD_SIZE];
    char url[MAX_URL];
};

int extract_http_info(ci_request_t * , ci_headers_list_t * , struct http_info *);
const char *http_content_type(ci_request_t * );
void free_global();
void generate_redirect_page(char * , ci_request_t * , scas_req_data_t *);
void generate_response_page(ci_request_t * , scas_req_data_t *);
#ifdef HAVE_CICAP_TEMPLATE
void cfgreload_command(const char *name, int type, const char **argv);
#else
void cfgreload_command(char *name, int type, char **argv);
#endif

/* ----------------------------------------------------- */

int squidscas_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf) {
    unsigned int xops;

    debugs(10, "DEBUG squidscas_init_service\n");
    debugs(2, "DEBUG Going to initialize squidscas\n");

    pthread_mutex_init(&MUTEX, NULL);
    squidscas_xdata = srv_xdata;
    set_istag(squidscas_xdata);
    ci_service_set_preview(srv_xdata, 1024);
    ci_service_enable_204(srv_xdata);
    ci_service_set_transfer_preview(srv_xdata, "*");

    xops = CI_XCLIENTIP | CI_XSERVERIP;
    xops |= CI_XAUTHENTICATEDUSER | CI_XAUTHENTICATEDGROUPS;
    ci_service_set_xopts(srv_xdata, xops);

    /*Initialize object pools*/
    AVREQDATA_POOL = ci_object_pool_register("scas_req_data_t", sizeof(scas_req_data_t));

    if (AVREQDATA_POOL < 0) {
        debugs(0, "FATAL error registering object_pool scas_req_data_t\n");
        return CI_ERROR;
    }

    /* Reload configuration command */
    register_command("squidscas:cfgreload", MONITOR_PROC_CMD | CHILDS_PROC_CMD, cfgreload_command);

    /*********************
      read config files
     ********************/
    if (load_patterns() != S_OK) {
        return CI_ERROR;
    }

    return CI_OK;
}

#ifdef HAVE_CICAP_TEMPLATE
void cfgreload_command(const char *name, int type, const char **argv)
#else
void cfgreload_command(char *name, int type, char **argv)
#endif
{
    debugs(0, "LOG reload configuration command received\n");

    free_global();
    statit = 0;

    pattc = 0;
    current_pattern_size = 0;
    maxsize = 0;
    dnslookup = 1;
    scan_mode = 1;

    /* read configuration file */
    if (load_patterns() != S_OK)
        debugs(0, "FATAL reload configuration command failed!\n");
    if (squidscas_xdata)
        set_istag(squidscas_xdata);
}

int squidscas_post_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf) {
    debugs(10, "DEBUG squidscas_post_init_service\n");

    /* SECIOSS */
    const mc_server_t *srv;
    const char *default_servers[] = {
        "127.0.0.1",
        NULL
    };

    if (mamcache_servers_list == NULL) {
        mc_cfg_servers_set(default_servers);
        if (mamcache_servers_list == NULL)
            return CI_ERROR;
    }

    MC = memcached_create(NULL);
    if (MC == NULL) {
        debugs(0, "FATAL Failed to create memcached instance\n");
        return CI_ERROR;
    }

    for (srv = (const mc_server_t *)ci_list_first(mamcache_servers_list); srv != NULL; srv=(const mc_server_t *)ci_list_next(mamcache_servers_list)) {
        if (srv->hostname[0] == '/') {
            if (memcached_server_add_unix_socket(MC, srv->hostname) != MEMCACHED_SUCCESS) {
                debugs(1, "FATAL Failed to add socket path to the server pool\n");
                memcached_free(MC);
                MC = NULL;
                return CI_ERROR;
            }
        } else if (memcached_server_add(MC, srv->hostname, srv->port) !=
            MEMCACHED_SUCCESS) {
            debugs(1, "FATAL Failed to add localhost to the server pool\n");
            memcached_free(MC);
            MC = NULL;
            return CI_ERROR;
        }
    }

    MC_POOL = memcached_pool_create(MC, 5, 500);
    if (MC_POOL == NULL) {
        debugs(1, "FATAL Failed to create connection pool\n");
        memcached_free(MC);
        MC = NULL;
        return CI_ERROR;
    }

    if (authz_api[0]) {
        curl_global_init(CURL_GLOBAL_SSL);
    }

    return CI_OK;
}

void squidscas_close_service() {
    debugs(10, "DEBUG squidscas_close_service\n");
    debugs(2, "DEBUG clean all memory!\n");
    free_global();
    debugs(9, "DEBUG curl_global_cleanup\n");
    curl_global_cleanup();
    debugs(9, "DEBUG ci_object_pool_unregister\n");
    ci_object_pool_unregister(AVREQDATA_POOL);
    debugs(2, "DEBUG clean all memory! -end\n");
}

void *squidscas_init_request_data(ci_request_t *req) {
    scas_req_data_t *data;

    debugs(10, "DEBUG squidscas_init_request_data\n");
    debugs(2, "DEBUG initializing request data handler.\n");

    if (!(data = ci_object_pool_alloc(AVREQDATA_POOL))) {
        debugs(0, "FATAL Error allocation memory for service data!!!");
        return NULL;
    }
    data->body = NULL;
    data->url = NULL;
    data->clientip = NULL;
    data->user = NULL;
    data->error_page = NULL;
    data->service = NULL;
    data->operation = NULL;
    data->allowed = NULL;
    data->share_user = NULL;
    data->req = req;
    data->blocked = 0;
    data->no_more_scan = 0;
    data->virus = 0;

    return data;
}

void squidscas_release_request_data(void *data) {
    debugs(10, "DEBUG squidscas_release_request_data\n");

    if (data) {
        debugs(2, "DEBUG Releasing request data.\n");

        if (((scas_req_data_t * ) data) -> body)
            ci_simple_file_destroy(((scas_req_data_t * ) data) -> body);
        if (((scas_req_data_t * ) data) -> url)
            ci_buffer_free(((scas_req_data_t * ) data) -> url);
        if (((scas_req_data_t * ) data) -> user)
            ci_buffer_free(((scas_req_data_t * ) data) -> user);
        if (((scas_req_data_t * ) data) -> clientip)
            ci_buffer_free(((scas_req_data_t * ) data) -> clientip);
        if (((scas_req_data_t * ) data) -> error_page)
            ci_membuf_free(((scas_req_data_t * ) data) -> error_page);
        if (((scas_req_data_t * ) data) -> operation)
            ci_buffer_free(((scas_req_data_t * ) data) -> operation);
        if (((scas_req_data_t * ) data) -> allowed)
            ci_buffer_free(((scas_req_data_t * ) data) -> allowed);
        if (((scas_req_data_t * ) data) -> share_user)
            ci_buffer_free(((scas_req_data_t * ) data) -> share_user);

        ci_object_pool_free(data);
    }
}

int squidscas_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t *req) {
    debugs(2, "DEBUG squidscas_check_preview_handler\n");

    ci_headers_list_t *req_header;
    struct http_info httpinf;
    scas_req_data_t *data = ci_service_data(req);
    const char *clientip;
    struct hostent *clientname;
    unsigned long ip;
    const char *username;
    int chkipdone = 0;
    int ret = CI_MOD_ALLOW204;

    debugs(2, "DEBUG processing preview header.\n");

    if (preview_data_len) {
        debugs(2, "DEBUG preview data size is %d\n", preview_data_len);
    }

    /* Extract the HTTP header from the request */
    if ((req_header = ci_http_request_headers(req)) == NULL) {
        debugs(1, "WARNING bad http header, can not check URL, Content-Type and Content-Length.\n");
        return CI_MOD_ERROR;
    }

    int scanit = scan_mode == SCAN_ALL ? 1 : 0;
    int content_length = 0;
    const char *content_type = NULL;
    const char *content_disposition = NULL;
    char file_extension[PATH_MAX];
    ci_headers_list_t *req_eh = NULL;
    ci_headers_list_t *res_eh = NULL;
    const char *user_agent = NULL;
    scas_url_t *url = NULL;
    const scas_service_t *service;
    const char *service_id = NULL;
    char ** tokens;
    char *operation = "view";
    memcached_return rc;
    memcached_st *mlocal;
    uint32_t flags;
    char key[1024];
    char mckey[MC_MAXKEYLEN + 1];
    int mckeylen = 0;
    char * value;
    size_t value_len;
    SHA_CTX sha1;
    unsigned char digest[20];
    int no_acl = 1;
    int i;

    /* Get the Authenticated user */
    if ((username = ci_headers_value(req->request_header, "X-Authenticated-User")) != NULL) {
        debugs(2, "DEBUG X-Authenticated-User: %s\n", username);
        if (scan_mode == SCAN_ALL) {
            /* if a TRUSTUSER match => no virus scan */
            if (simple_pattern_compare(username, TRUSTUSER) == 1) {
                debugs(2, "DEBUG No antivir check (TRUSTUSER match) for user: %s\n", username);
                scanit = 0;
            }
        } else {
            /* if a UNTRUSTUSER match => virus scan */
            if (simple_pattern_compare(username, UNTRUSTUSER) == 1) {
                debugs(2, "DEBUG antivir check (UNTRUSTUSER match) for user: %s\n", username);
                scanit = 1;
            }
        }
    } else {
        debugs(1, "ERROR username is null, you must set 'icap_send_client_username on' into squid.conf\n");
        return CI_MOD_ERROR;
    }

    /* Check client Ip against SeciossCAS trustclient */
    if ((clientip = ci_headers_value(req->request_header, "X-Client-IP")) != NULL) {
        debugs(2, "DEBUG X-Client-IP: %s\n", clientip);
        ip = inet_addr(clientip);
        chkipdone = 0;
        if (dnslookup == 1) {
            if ((clientname = gethostbyaddr((char * ) & ip, sizeof(ip), AF_INET)) != NULL) {
                if (clientname->h_name != NULL) {
                    if (scan_mode == SCAN_ALL) {
                        /* if a TRUSTCLIENT match => no virus scan */
                        if (client_pattern_compare(clientip, clientname->h_name) > 0) {
                            debugs(2, "DEBUG no antivir check (TRUSTCLIENT match) for client: %s(%s)\n", clientname->h_name, clientip);
                            scanit = 0;
                        }
                    } else {
                        /* if a UNTRUSTCLIENT match => virus scan */
                        if (client_pattern_compare(clientip, clientname->h_name) > 0) {
                            debugs(2, "DEBUG antivir check (UNTRUSTCLIENT match) for client: %s(%s)\n", clientname->h_name, clientip);
                            scanit = 1;
                        }
                    }
                    chkipdone = 1;
                }
            }
        }
        if (chkipdone == 0) {
            if (scan_mode == SCAN_ALL) {
                /* if a TRUSTCLIENT match => no virus scan */
                if (client_pattern_compare(clientip, NULL) > 0) {
                    debugs(2, "DEBUG No antivir check (TRUSTCLIENT match) for client: %s\n", clientip);
                    scanit = 0;
                }
            } else {
                /* if a UNTRUSTCLIENT match => virus scan */
                if (client_pattern_compare(clientip, NULL) > 0) {
                    debugs(2, "DEBUG antivir check (UNTRUSTCLIENT match) for client: %s\n", clientip);
                    scanit = 1;
                }
            }
        }
    }

    if ((req_eh = get_headers_from_entities(req->entities, ICAP_REQ_HDR)) == NULL) {
        debugs(1, "ERROR request headers in entities is null\n");
        return CI_MOD_ERROR;
    }

    if ((res_eh = get_headers_from_entities(req->entities, ICAP_RES_HDR))) {
        for (i=0; i<res_eh->used; i++) {
            debugs(5, "DEBUG Response Header %s\n", res_eh->headers[i]);
        }
    } else {
        for (i=0; i<req_eh->used; i++) {
            debugs(5, "DEBUG Request Header %s\n", req_eh->headers[i]);
        }
    }

    /* Get the user agent */
    if ((user_agent = ci_headers_value(req_eh, "User-Agent")) != NULL) {
        debugs(2, "DEBUG User-Agent: %s\n", user_agent);
    }

    /* Get the requested URL */
    if (extract_http_info(req, req_header, &httpinf) != S_OK) {
        /* Something wrong in the header or unknow method */
        debugs(1, "ERROR bad http header, aborting.\n");
        return CI_MOD_ERROR;
    }

    debugs(2, "DEBUG URL requested: %s\n", httpinf.url);

    /* CONNECT (https) and OPTIONS methods can not be scanned so abort */
    if ((strcmp(httpinf.method, "CONNECT") == 0) || (strcmp(httpinf.method, "OPTIONS") == 0)) {
        debugs(2, "DEBUG method %s can't be scanned.\n", httpinf.method);
        return CI_MOD_ALLOW204;
    }

    if (whitelist) {
        /* Check the URL against white list */
        int match = 0;
        for (url = (scas_url_t *)ci_list_first(whitelist); url != NULL; url = (scas_url_t *)ci_list_next(whitelist)) {
            if (!strncmp(httpinf.url, url->url, strlen(url->url))) {
                match = 1;
                break;
            }
        }
        if (match == 0) {
            debugs(2, "DEBUG %s matches with %s in the wihtelist\n", httpinf.url, url->url);
            data->code = 8;
            data->blocked = 1;
            generate_response_page(req, data);
            return CI_MOD_CONTINUE;
        }
    } else if (blacklist) {
        /* Check the URL against blacklist */
        for (url = (scas_url_t *)ci_list_first(blacklist); url != NULL; url = (scas_url_t *)ci_list_next(blacklist)) {
            if (!strncmp(httpinf.url, url->url, strlen(url->url))) {
                debugs(2, "DEBUG %s matches with %s in the blacklist\n", httpinf.url, url->url);
                data->code = 8;
                data->blocked = 1;
                generate_response_page(req, data);
                return CI_MOD_CONTINUE;
            }
        }
    }

    if (scan_mode == SCAN_ALL) {
        /* Check the URL against SeciossCAS abort */
        if (simple_pattern_compare(httpinf.url, ABORT) == 1) {
            debugs(5, "DEBUG No antivir check (ABORT match) for url: %s\n", httpinf.url);
            scanit = 0;
        }
    } else {
        /* Check the URL against SeciossCAS scan */
        if (simple_pattern_compare(httpinf.url, SCAN) == 1) {
            debugs(5, "DEBUG antivir check (SCAN match) for url: %s\n", httpinf.url);
            scanit = 1;
        }
    }

    /* Get the content type header */
    if ((content_type = http_content_type(req)) != NULL) {
        while (*content_type == ' ' || *content_type == '\t') content_type++;
        debugs(5, "DEBUG Content-Type: %s\n", content_type);
        if (scan_mode == SCAN_ALL) {
            /* Check the Content-Type against SeciossCAS abortcontent */
            if (simple_pattern_compare(content_type, ABORTCONTENT)) {
                debugs(5, "DEBUG No antivir check (ABORTCONTENT match) for content-type: %s\n", content_type);
                scanit = 0;
            }
        } else {
            /* Check the Content-Type against SeciossCAS scancontent */
            if (simple_pattern_compare(content_type, SCANCONTENT)) {
                debugs(5, "DEBUG No antivir check (SCANCONTENT match) for content-type: %s\n", content_type);
                scanit = 1;
            }
        }
    }

    /* get SECIOSS Service ID from url */
    for (service = (const scas_service_t *)ci_list_first(services_list); service != NULL; service = (const scas_service_t *)ci_list_next(services_list)) {
        for (i=0; i<NUM_OF_URLS && service->urls[i][0]; i++) {
            if (strstr(httpinf.url, service->urls[i]) != NULL) {
                service_id = service->id;
                data->service = service;
                break;
            }
        }
        if (service_id) {
            debugs(2, "DEBUG Service-ID: %s\n", service_id);
            break;
        }
    }

    if (strcmp(httpinf.method, "GET") == 0) {
        if (res_eh) {
            if ((content_disposition = ci_headers_value(res_eh, "Content-Disposition")) != NULL && (strstr(content_disposition, "filename=\"") != NULL || ci_headers_value(res_eh, "Etag"))) {
                debugs(2, "DEBUG Content-Disposition: %s\n", content_disposition);
                operation = "download";
            }
        }
    } else if (strcmp(httpinf.method, "POST") == 0 || strcmp(httpinf.method, "PUT") == 0) {
        char * s1 = NULL;
        char * s2 = NULL;
        char * tmp = NULL;

        content_disposition = ci_headers_value(req_eh, "Content-Disposition");
        if (content_disposition || (content_type && strncmp(content_type, "multipart/", 10) == 0 && strstr(content_type, "boundary=batch_") == NULL)) {
            operation = "upload";
        }
        if (content_disposition) {
            debugs(2, "DEBUG Content-Disposition: %s\n", content_disposition);
        } else if (service_id) {
            for (i=0; i<req_eh-> used; i++) {
                debugs(3, "DEBUG Header %s\n", req_eh->headers[i]);
                if (strcmp(service_id, "storage/office365_drive") == 0 && strcmp(req_eh->headers[i], "Scenario: UploadFile") == 0) {
                    // OneDrive
                    operation = "upload";
                    s1 = strstr(httpinf.url, "&@a2=");
                    if (s1) {
                        s2 = strchr(s1 + 1, (int)'&');
                        if (s2) {
                            s2 -= 3;
                            while ((tmp = strstr(s1, "%2E")) != NULL) {
                                if (tmp < s2) {
                                    s1 = tmp + 3;
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    break;
                } else if (strcmp(service_id, "iaas/aws") == 0 && ci_headers_value(req_eh, "Content-MD5")) {
                    // AWS S3
                    operation = "upload";
                    s2 = strchr(httpinf.url, (int)'?');
                    if (s2) {
                        s1 = httpinf.url;
                        while ((tmp = strchr(s1, (int)'.')) != NULL) {
                            if (tmp < s2) {
                                s1 = tmp + 1;
                            } else {
                                break;
                            }
                        }
                    }
                    break;
                } else if (strcmp(service_id, "storage/dropbox") == 0 && strcmp(content_type, "application/octet-stream") == 0) {
                    // Dropbox
                    operation = "upload";
                    break;
                }
            }
            if (s1 && s2) {
                file_extension[0] = '|';
                strncpy(file_extension + 1, s1, s2 - s1);
                file_extension[s2 - s1 + 1] = '|';
                file_extension[s2 - s1 + 2] = '\0';
                tolowerstring(file_extension);
            }
        }
    }

    if (MC && service_id) {
        char buf[1024];
        char * s1 = NULL;
        char * s2 = NULL;
        char ** elts = NULL;
        regmatch_t * match_buf;
        size_t size;
        char allowed[20] = "";
        int personal = 0;
        int forbidden = -1;
        int match;
        char ** user_values;
        char loginid[ID_LEN];
        char login_domain[MAX_DOMAIN];
        char share_user[ID_LEN * 10];

        memset(loginid, 0, sizeof(loginid));
        memset(login_domain, 0, sizeof(login_domain));
        memset(share_user, 0, sizeof(share_user));

        debugs(2, "DEBUG service id requested: %s\n", service_id);

        if (user_agent == NULL) {
            debugs(1, "ERROR user_agent is null in %s\n", httpinf.url);
            return CI_MOD_ERROR;
        }

        if (service->update_urls[0] && (strcmp(httpinf.method, "POST") == 0 || strcmp(httpinf.method, "PUT") == 0 || strcmp(httpinf.method, "DELETE") == 0)) {
            for (i = 0; i<NUM_OF_URLS; i++) {
                if (service->update_urls[i] && strstr(httpinf.url, service->update_urls[i]) != NULL) {
                    if (service->update_params[i]) {
                        operation = "is_update";
                    } else {
                        operation = "update";
                    }
                }
            }
        }
        
        if (service->share && (strcmp(httpinf.method, "POST") == 0 || strcmp(httpinf.method, "PUT") == 0) && regexec(&service->share_url, httpinf.url, 0, NULL, 0) == 0) {
            if (!strcmp(operation, "update") || !strcmp(operation, "is_update")) {
                operation = "update_share";
            } else {
                operation = "share";
            }
        }

        if ((s1 = strchr(username, (int)'@')) != NULL) {
            mckeylen = sprintf(mckey, "secioss_cas:service_acl_%s", s1 + 1);
            s2 = strchr(mckey, (int)'/');
            if (s2) {
                mckey[s2 - mckey] = '\0';
            }
        } else {
            mckeylen = sprintf(mckey, "secioss_cas:service_acl");
        }

        mlocal = memcached_pool_pop(MC_POOL, true, &rc);
        if (!mlocal) {
            debugs(1, "Error getting memcached_st object from pool: %s\n", memcached_strerror(MC, rc));
            return CI_MOD_ERROR;
        }

        value = memcached_get(mlocal, mckey, mckeylen, & value_len, & flags, & rc);
        if (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND) {
            debugs(1, "ERROR Failed to retrieve %s object from cache: %s\n", mckey, memcached_strerror(mlocal, rc));
            return CI_MOD_ERROR;
        }

        if ((rc = memcached_pool_push(MC_POOL, mlocal)) != MEMCACHED_SUCCESS) {
            debugs(1, "ERROR Failed to release memcached_st object (%s)!\n", memcached_strerror(MC, rc));
        }

        if (value == NULL && authz_api[0]) {
            value = authorization("acl", username, clientip, user_agent);
            if (value == NULL) {
                debugs(1, "ERROR Failed to retrieve acl(%s) from API\n", username);
                return CI_MOD_ERROR;
            }
        }
        if (value) {
            sprintf(buf, "%s:", service_id);
            if (strstr(value, buf) != NULL) {
                no_acl = 0;
            } else {
                s1 = strchr(buf, (int)'/');
                if (s1) {
                    buf[s1 - buf + 1] = ':';
                    buf[s1 - buf + 2] = '\0';
                    if (strstr(value, buf) != NULL) {
                        no_acl = 0;
                    }
                }
            }
            if (strstr(value, "function:antivirus") == NULL) {
                scanit = 0;
            }
            free(value);
        }

        if (no_acl) {
            debugs(2, "DEBUG No service acl: %s\n", service_id);
        } else {
            if (content_disposition) {
                if ((s1 = strstr(content_disposition, "filename=\"")) != NULL) {
                    s1 = strchr(s1, '"');
                    s2 = strchr(s1 + 1, '"');
                    for (i = 1; s2 - i > s1; i++) {
                        if ( * (s2 - i) == '.') {
                            s1 = s2 - i;
                            break;
                        }
                    }
                    if (i > 0) {
                        file_extension[0] = '|';
                        strncpy(file_extension + 1, s1 + 1, i - 1);
                        file_extension[i] = '|';
                        file_extension[i + 1] = '\0';
                        tolowerstring(file_extension);
                    }
                }
            }

            if (clientip) {
                sprintf(key, "%s%s%s", username, clientip, user_agent);
            } else {
                sprintf(key, "%s", username);
            }

            SHA1_Init( & sha1);
            SHA1_Update( & sha1, (const unsigned char * ) key, strlen(key));
            SHA1_Final(digest, & sha1);
            mckeylen = sprintf(mckey, "secioss_cas:%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                digest[0], digest[1], digest[2], digest[3],
                digest[4], digest[5], digest[6], digest[7],
                digest[8], digest[9], digest[10], digest[11],
                digest[12], digest[13], digest[14], digest[15],
                digest[16], digest[17], digest[18], digest[19]);

            mlocal = memcached_pool_pop(MC_POOL, true, &rc);
            if (!mlocal) {
                debugs(1, "Error getting memcached_st object from pool: %s\n", memcached_strerror(MC, rc));
                return CI_MOD_ERROR;
            }

            value = memcached_get(mlocal, mckey, mckeylen, & value_len, & flags, & rc);
            if (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND) {
                debugs(1, "ERROR Failed to retrieve %s(%s %s %s) object from cache: %s\n", mckey, username, clientip, user_agent, memcached_strerror(mlocal, rc));
                return CI_MOD_ERROR;
            }

            if ((rc = memcached_pool_push(MC_POOL, mlocal)) != MEMCACHED_SUCCESS) {
                debugs(1, "ERROR Failed to release memcached_st object (%s)!\n", memcached_strerror(MC, rc));
            }

            if (value == NULL && authz_api[0]) {
                value = authorization("token", username, clientip, user_agent);
                if (value == NULL) {
                    debugs(1, "ERROR Failed to retrieve token(%s %s %s) from API\n", username, clientip, user_agent);
                    return CI_MOD_ERROR;
                }
            }

            if (value) {
                debugs(2, "DEBUG tokens(%s %s %s) is %s\n", username, clientip, user_agent, value);
                elts = split(value, '#');
                free(value);
                data -> code = atoi(elts[0]);
                if (data -> code != 0) {
                    data -> blocked = 1;
                    generate_response_page(req, data);
                    return CI_MOD_CONTINUE;
                }

                if (service->login_url[0] && strcmp(httpinf.method, "POST") == 0 && strstr(httpinf.url, service->login_url) != NULL) {
                    size = service->login_regexv.re_nsub + 1;
                    match_buf = malloc(sizeof(regmatch_t) * size);
                    if (regexec(&service->login_regexv, preview_data, size, match_buf, 0) == 0) {
                        user_values = split(elts[2], ',');
                        strncpy(buf, preview_data + match_buf[1].rm_so, match_buf[1].rm_eo - match_buf[1].rm_so);
                        buf[match_buf[1].rm_eo - match_buf[1].rm_so] = '\0';
                        if (urldecode(buf, loginid, sizeof(loginid)) < 0) {
                            debugs(1, "ERROR url deocde failed: %s\n", buf);
                        } else {
                            s1 = strchr(loginid, (int)'@');
                            if (s1) {
                                s1++;
                                snprintf(login_domain, sizeof(login_domain), "|%s|", s1);
                            }

                            personal = 1;
                            for (i = 0; user_values[i] != NULL; i++) {
                                if (strcasecmp(user_values[i], loginid) == 0) {
                                    personal = 0;
                                    break;
                                }
                            }
                        }
                        operation = "login";
                        free(user_values);
                    }
                    free(match_buf);
                }

                tokens = split(elts[1], ',');
                for (i = 0; tokens[i] != NULL; i++) {
                    char **sprited = split(tokens[i], '=');
                    if (!strcmp(service_id, sprited[0]) || (sprited[0][strlen(sprited[0]) - 1] == '/' && !strncmp(service_id, sprited[0], strlen(sprited[0])))) {
                        match = 1;
                        if (!sprited[1]) {
                            debugs(1, "ERROR invalid token %s\n", tokens[i]);
                            continue;
                        }
                        if (strstr(sprited[1], "+enterprise+") != NULL && personal) {
                            match = 0;
                        }
                        if (strstr(sprited[1], "+personal+") != NULL && !personal) {
                            match = 0;
                        }

                        if (strstr(sprited[1], "+update+") != NULL && strstr(allowed, "update") == NULL) {
                            strcat(allowed, "+update");
                        }
                        if (!strcmp(operation, "login") && (s2 = strstr(sprited[1], "+login_domain")) != NULL) {
                            if (login_domain[0]) {
                                if (strstr(s2, login_domain) == NULL) {
                                    match = 0;
                                }
                            } else {
                                match = 0;
                            }
                        }
                        if (strstr(sprited[1], "+shared+") != NULL) {
                            if (strstr(allowed, "share") == NULL) {
                                strcat(allowed, "+share");
                            }
                            if ((s2 = strstr(sprited[1], "+share_user")) != NULL) {
                                char **share_user_splited = split(s2 + 1, '+');
                                strncat(share_user, share_user_splited[0], sizeof(share_user));
                                strncat(share_user, " ", sizeof(share_user));
                                free(share_user_splited);
                            }
                        }
                        if (strstr(sprited[1], "+view+") != NULL && strstr(allowed, "view") == NULL) {
                            strcat(allowed, "+view");
                        }

                        if (!strcmp(operation, "update") && strstr(sprited[1], "+update+") == NULL) {
                            match = 0;
                        } else if (!strcmp(operation, "download") && strstr(sprited[1], "+download+") == NULL) {
                            match = 0;
                        } else if (!strcmp(operation, "upload") && strstr(sprited[1], "+upload+") == NULL) {
                            match = 0;
                        } else if (!strcmp(operation, "view") && strstr(sprited[1], "+view+") == NULL) {
                            match = 0;
                        }
                        if (match && file_extension[0]  && (!strcmp(operation, "download") || !strcmp(operation, "upload")) && (s2 = strstr(sprited[1], "+fileext")) != NULL) {
                            if (strstr(s2, file_extension) == NULL) {
                                match = 0;
                            }
                        }
                        if (match) {
                            forbidden = 0;
                        } else if (forbidden < 0) {
                            forbidden = 1;
                        }
                    }
                    free(sprited);
                }
                data -> allowed = ci_buffer_alloc(strlen(allowed) + 1);
                strcpy(data -> allowed, allowed);
                if (share_user[0]) {
                    data -> share_user = ci_buffer_alloc(strlen(share_user) + 1);
                    xstrncpy(data->share_user, share_user, strlen(share_user));
                }
                free(tokens);
                free(elts);
            }

            if (forbidden != 0) {
                if (!strcmp(operation, "login")) {
                    debugs(0, "NOTICE %s; %s; %s; login; login with %s is denied\n", clientip, username, service_id, loginid);
                } else {
                    debugs(0, "NOTICE %s; %s; %s; %s; %s is denied\n", clientip, username, service_id, operation, operation);
                }
                data -> code = 8;
                data -> blocked = 1;
                generate_response_page(req, data);
                return CI_MOD_CONTINUE;
            }
        }
        if (!strcmp(operation, "login")) {
            debugs(0, "NOTICE %s; %s; %s; login; login with %s is allowed\n", clientip, username, service_id, loginid);
        }
    }

    debugs(5, "DEBUG Operation: %s\n", operation);
    
    /* Get the content length header */
    content_length = ci_http_content_length(req);
    if ((content_length > 0) && (maxsize > 0) && (content_length >= maxsize)) {
        debugs(2, "DEBUG No antivir check, content-length upper than maxsize (%" PRINTF_OFF_T " > %d)\n", (CAST_OFF_T) content_length, (int) maxsize);
        return ret;
    }

    /* No data, so nothing to scan */
    if (!data || !ci_req_hasbody(req)) {
        debugs(2, "DEBUG No body data, allow 204\n");
        return ret;
    }

    if (data->service == NULL) {
        debugs(5, "DEBUG No secioss service, allow 204\n");
        return ret;
    }

    if (mail_export_path[0]) {
        if (!strncmp(service_id, "mail/", 5)) {
            // service id is starts with mail/
            ret = CI_MOD_CONTINUE;
        }
    }
    
    if (!strcmp(operation, "download") || !strcmp(operation, "upload")) {
        /* Get out if we have not detected something to scan */
        if (scanit == 0) {
            debugs(0, "NOTICE %s; %s; %s; %s; %s is allowed\n", clientip, username, service_id, operation, operation);
        }
    } else if (strstr(operation, "share") == NULL && (no_acl || strcmp(operation, "is_update"))) {
        debugs(0, "NOTICE %s; %s; %s; %s; %s is allowed\n", clientip, username, service_id, operation, operation);
    }

    if (ret == CI_MOD_ALLOW204) {
        return ret;
    }
    ret = CI_MOD_CONTINUE;

    data->url = ci_buffer_alloc(strlen(httpinf.url) + 1);
    strcpy(data->url, httpinf.url);

    data->user = ci_buffer_alloc(strlen(username) + 1);
    strcpy(data->user, username);

    if (clientip) {
        data->clientip = ci_buffer_alloc(strlen(clientip) + 1);
        strcpy(data->clientip, clientip);
    }

    data->operation = ci_buffer_alloc(strlen(operation) + 1);
    strcpy(data->operation, operation);

    if (preview_data_len == 0) {
        debugs(2, "DEBUG Can not begin to scan url: No preview data.\n");
    }

    data->body = ci_simple_file_new(0);
    if ((SEND_PERCENT_BYTES >= 0) && (START_SEND_AFTER == 0)) {
        ci_req_unlock_data(req);
        ci_simple_file_lock_all(data->body);
    }
    if (!data->body) {
        debugs(5, "DEBUG No body\n");
        return CI_ERROR;
    }

    if (preview_data_len) {
        if (ci_simple_file_write(data->body, preview_data, preview_data_len, ci_req_hasalldata(req)) == CI_ERROR) {
            debugs(1, "Error failed in ci_simple_file_write\n");
            return CI_ERROR;
        }
    }

    debugs(2, "DEBUG End of method squidscas_check_preview_handler\n");

    return ret;
}

int squidscas_read_from_net(char *buf, int len, int iseof, ci_request_t *req) {
    scas_req_data_t *data = ci_service_data(req);
    int allow_transfer;

    if (!data)
        return CI_ERROR;

    if (!data->body)
        return len;

    if (data->no_more_scan == 1) {
        return ci_simple_file_write(data->body, buf, len, iseof);
    }

    if ((maxsize > 0) && (data->body->bytes_in >= maxsize)) {
        data->no_more_scan = 1;
        ci_req_unlock_data(req);
        ci_simple_file_unlock_all(data->body);
        debugs(1, "LOG No more antivir check, downloaded stream is upper than maxsize (%d>%d)\n", (int) data->body->bytes_in, (int) maxsize);
    } else if (SEND_PERCENT_BYTES && (START_SEND_AFTER < data->body->bytes_in)) {
        ci_req_unlock_data(req);
        allow_transfer = (SEND_PERCENT_BYTES * (data->body->endpos + len)) / 100;
        ci_simple_file_unlock(data->body, allow_transfer);
    }

    return ci_simple_file_write(data->body, buf, len, iseof);
}

int squidscas_write_to_net(char *buf, int len, ci_request_t *req) {
    int bytes;
    scas_req_data_t *data = ci_service_data(req);

    if (!data)
        return CI_ERROR;

    if (data->blocked == 1 && data->error_page == 0) {
        debugs(2, "DEBUG ending here, content was blocked\n");
        return CI_EOF;
    }

    /* if a virus was found or the page has been blocked, a warning page
       has already been generated */
    if (data->error_page)
        return ci_membuf_read(data->error_page, buf, len);

    if (data->body)
        bytes = ci_simple_file_read(data->body, buf, len);
    else
        bytes = 0;

    return bytes;
}

int squidscas_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t *req) {
    debugs(10, "DEBUG squidscas_io\n");

    if (rbuf && rlen) {
        *rlen = squidscas_read_from_net(rbuf, *rlen, iseof, req);
        if ( *rlen == CI_ERROR)
            return CI_ERROR;
        else if ( *rlen < 0)
            return CI_OK;
    } else if (iseof) {
        if (squidscas_read_from_net(NULL, 0, iseof, req) == CI_ERROR)
            return CI_ERROR;
    }

    if (wbuf && wlen) {
        *wlen = squidscas_write_to_net(wbuf, *wlen, req);
    }

    return CI_OK;
}

int squidscas_end_of_data_handler(ci_request_t *req) {
    debugs(10, "DEBUG squidscas_end_of_data_handler\n");

    scas_req_data_t *data = ci_service_data(req);
    ci_simple_file_t *body;

    /* If local path was specified then generate unique file name to copy data.
    It can be used to put banned files and viri in quarantine directory. */
    char mime[LOW_BUFF];
    char checksum[LOW_BUFF];
    const scas_virus_t *virus;
    char fileref[SMALL_BUFF];
    char targetf[MAX_URL];
    char *s;
    int ret = 0;

    debugs(2, "DEBUG ending request data handler.\n");

    /* Nothing more to scan */
    if (!data || !data->body){
        debugs(5, "DEBUG No data body.\n");
        return CI_MOD_DONE;
    }

    if (data->blocked == 1) {
        debugs(2, "DEBUG blocked content, sending redirection header / error page.\n");
        return CI_MOD_DONE;
    }

    body = data->body;
    if (data->no_more_scan == 1) {
        debugs(2, "DEBUG no more data to scan, sending content.\n");
        ci_simple_file_unlock_all(body);
        return CI_MOD_DONE;
    }

    if (mail_export_path[0]) {
        if (!strncmp(data->service->id, "mail/", 5)) {
            const char *body = ci_simple_file_to_const_string(data->body);
            if (strlen(body) > 16) {
                debugs(5, "DEBUG export mail body.\n");
                
                time_t ltime;
                time(&ltime);
                struct tm *tm = localtime(&ltime);
                char path[PATH_MAX];
                snprintf(path, sizeof(path), "%s/%04d%02d%02d", mail_export_path, tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday);
                debugs(9, "DEBUG mkdir %s\n", path);
                mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH | S_IXOTH);
                snprintf(path, sizeof(path), "%s/%04d%02d%02d/%02d%02d%02d_%s_%s.mail", mail_export_path, tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, data->operation, data->user);
                debugs(9, "DEBUG create file %s\n", path);
                FILE *fp;
                if ((fp = fopen(path, "wb"))) {
                    fprintf(fp, "%s", body);
                    fclose(fp);
                }
            }
        }
    }

    if (data->service != NULL && (!strcmp(data->operation, "is_update") || !strcmp(data->operation, "share") || !strcmp(data->operation, "update_share"))) {
        char buf[HIGH_BUFF];
        ssize_t nread;
        regmatch_t *match_buf;
        size_t size;
        char *share_users = NULL;
        char *share_user = NULL;
        char *share_mail = NULL;
        char *share_domain = NULL;
        char *s1, *s2;
        int i;
        int match = 0;
        int forbidden = 0;

        lseek(body->fd, 0, SEEK_SET);
        nread = read(body->fd, buf, sizeof(buf));
        if (nread) {
            if (data->allowed != NULL && (!strcmp(data->operation, "is_update") || !strcmp(data->operation, "update_share"))) {
                for (i = 0; i<NUM_OF_URLS; i++) {
                    if (data->service->update_urls[i] && strstr(data->url, data->service->update_urls[i]) != NULL) {
                        if (data->service->update_params[i]) {
                            if (strstr(buf, data->service->update_params[i])) {
                                if (strstr(data->allowed, "update") == NULL) {
                                    forbidden = 1;
                                }
                                match = 1;
                            }
                        } else {
                            if (strstr(data->allowed, "update") == NULL) {
                                forbidden = 1;
                            }
                            match = 1;
                        }
                        if (match) {
                            if (forbidden) {
                                debugs(0, "NOTICE %s; %s; %s; update; update is denied\n", data->clientip, data->user, data->service->id);
                                generate_response_page(req, data);
                            } else {
                                debugs(0, "NOTICE %s; %s; %s; update; update is allowed\n", data->clientip, data->user, data->service->id);
                            }
                            break;
                        }
                    }
                }
            }

            if (match == 0 && (!strcmp(data->operation, "share") || !strcmp(data->operation, "update_share"))) {
                size = data->service->share_regexv.re_nsub + 1;
                match_buf = malloc(sizeof(regmatch_t) * size);
                s1 = buf;
                for (i = 0; i < 100; i++) {
                    match_buf = malloc(sizeof(regmatch_t) * size);
                    if (regexec( & data->service->share_regexv, s1, size, match_buf, 0)) {
                        break;
                    }

                    share_user = malloc(match_buf[1].rm_eo - match_buf[1].rm_so + 1);
                    strncpy(share_user, s1 + match_buf[1].rm_so, match_buf[1].rm_eo - match_buf[1].rm_so);
                    share_user[match_buf[1].rm_eo - match_buf[1].rm_so] = '\0';
                    if (share_users) {
                        share_users = realloc(share_users, strlen(share_users) + strlen(share_user) + 2);
                        strcat(share_users, ",");
                        strcat(share_users, share_user);
                    } else {
                        share_users = malloc(strlen(share_user) + 1);
                        strcpy(share_users, share_user);
                    }
                    if (data->share_user) {
                        share_mail = malloc(strlen(share_user) + 3);
                        sprintf(share_mail, "|%s|", share_user);
                        s2 = strchr(share_user, (int)'@');
                        if (s2 != NULL) {
                            s2++;
                            share_domain = malloc(strlen(s2) + 3);
                            sprintf(share_domain, "|%s|", s2);
                        } else {
                            share_domain = NULL;
                        }
                        if (strstr(data->share_user, share_mail) == NULL && (share_domain == NULL || strstr(data->share_user, share_domain) == NULL)) {
                            forbidden = 1;
                        }
                        free(share_mail);
                        if (share_domain) {
                            free(share_domain);
                        }
                    }
                    s1 = s1 + match_buf[1].rm_eo + 1;
                    match = 1;
                    free(share_user);
                }
                if (match) {
                    if (data->allowed != NULL && strstr(data->allowed, "share") == NULL) {
                        forbidden = 1;
                    }
                }
                if (share_users) {
                    if (forbidden) {
                        debugs(0, "NOTICE %s; %s; %s; share; share with %s is denied\n", data->clientip, data->user, data->service->id, share_users);
                        generate_response_page(req, data);
                    } else {
                        debugs(0, "NOTICE %s; %s; %s; share; share with %s is allowed\n", data->clientip, data->user, data->service->id, share_users);
                    }
                    free(share_users);
                }
            }

            if (match == 0) {
                debugs(0, "NOTICE %s; %s; %s; view; view is allowed\n", data->clientip, data->user, data->service->id);
            }
        }

        ci_simple_file_unlock_all(body);
        return CI_MOD_DONE;
    }

    lseek(body->fd, 0, SEEK_SET);
    ret = mimetype(body->fd, mime);
    if (ret == 0 && (strncmp(mime, "text/", 5) == 0 || strncmp(mime, "image/", 6) == 0)) {
        debugs(2, "DEBUG mime type \"%s\" is not scanned.\n", mime);
        ci_simple_file_unlock_all(body);
        return CI_MOD_DONE;
    }

    if (virus_list) {
        lseek(body->fd, 0, SEEK_SET);
        sha1sum(body->fd, checksum);
        for (virus = (scas_virus_t * ) ci_list_first(virus_list); virus != NULL; virus = (scas_virus_t * ) ci_list_next(virus_list)) {
            if (strcmp(checksum, virus->checksum) == 0) {
                data->virus = 1;
                debugs(1, "LOG Virus found in %s ending download to %s [%s]\n", data->url, data->user, virus->id);
                generate_response_page(req, data);
                return CI_MOD_DONE;
            }
        }
    }

    if (data->service != NULL) {
        debugs(0, "NOTICE %s; %s; %s; %s; %s is allowed\n", data->clientip, data->user, data->service->id, data->operation, data->operation);
    }

    /* Copy file */
    srand(time(NULL));
    if (has_invalid_chars(INVALID_CHARS, get_filename_ext(data->url)) == 1) {
        snprintf(fileref, sizeof(fileref), "%s%s_%s_%d_%d", PREFIX_SCAN, data->user, data->clientip, (int) time(NULL), (int) rand() % 99);
    } else {
        snprintf(fileref, sizeof(fileref), "%s%s_%s_%d_%d.%s", PREFIX_SCAN, data->user, data->clientip, (int) time(NULL), (int) rand() % 99, get_filename_ext(data->url));
    }
    s = strchr(fileref, '/');
    if (s != NULL) {
        *s = '#';
    }
    lseek(body->fd, 0, SEEK_SET);
    snprintf(targetf, sizeof(targetf), "%s/%s", scan_path, fileref);
    ret = copy_file(body->fd, targetf);
    debugs(1, "LOG Copied [%s] to [%s] with exit code [%d].\n", data->url, targetf, ret);

    if (!ci_req_sent_data(req) && ci_req_allow204(req)) {
        debugs(2, "DEBUG Responding with allow 204\n");
        return CI_MOD_ALLOW204;
    }

    debugs(3, "DEBUG unlocking data to be sent.\n");
    ci_simple_file_unlock_all(body);

    return CI_MOD_DONE;
} 
 
void set_istag(ci_service_xdata_t *srv_xdata) {
    char istag[SERVICE_ISTAG_SIZE + 1];

    snprintf(istag, SERVICE_ISTAG_SIZE, "-%d-%s-%d%d", 1, "squidscas", 1, 0);
    istag[SERVICE_ISTAG_SIZE] = '\0';
    ci_service_set_istag(srv_xdata, istag);
    debugs(2, "DEBUG setting istag to %s\n", istag);
}

int simple_pattern_compare(const char *str, const int type) {
    int i = 0;

    /* pass througth all regex pattern */
    for (i = 0; i < pattc; i++) {
        if ((patterns[i].type == type) && (regexec(&patterns[i].regexv, str, 0, 0, 0) == 0)) {
            switch (type) {
            case ABORT:
                debugs(2, "DEBUG abort (%s) matched: %s\n", patterns[i].pattern, str);
                return 1;
                /* return 1 if string matches scan pattern */
            case SCAN:
                debugs(2, "DEBUG scan (%s) matched: %s\n", patterns[i].pattern, str);
                return 1;
                /* return 1 if string matches trustuser pattern */
            case TRUSTUSER:
                debugs(2, "DEBUG trustuser (%s) matched: %s\n", patterns[i].pattern, str);
                return 1;
                /* return 1 if string matches untrustuser pattern */
            case UNTRUSTUSER:
                debugs(2, "DEBUG untrustuser (%s) matched: %s\n", patterns[i].pattern, str);
                return 1;
                /* return 1 if string matches abortcontent pattern */
            case ABORTCONTENT:
                debugs(2, "DEBUG abortcontent (%s) matched: %s\n", patterns[i].pattern, str);
                return 1;
                /* return 1 if string matches scancontent pattern */
            case SCANCONTENT:
                debugs(2, "DEBUG scancontent (%s) matched: %s\n", patterns[i].pattern, str);
                return 1;
            default:
                debugs(1, "ERROR unknown pattern match type: %s\n", str);
                return -1;
            }
        }
    }

    /* return 0 otherwise */
    return 0;
}

int client_pattern_compare(const char *ip, char *name) {
    int i = 0;

    /* pass througth all regex pattern */
    for (i = 0; i < pattc; i++) {
        if ((scan_mode == SCAN_ALL) && (patterns[i].type == TRUSTCLIENT)) {
            /* Look at client ip pattern matching */
            /* return 1 if string matches ip TRUSTCLIENT pattern */
            if (regexec(&patterns[i].regexv, ip, 0, 0, 0) == 0) {
                debugs(2, "DEBUG trustclient (%s) matched: %s\n", patterns[i].pattern, ip);
                return 1;
                /* Look at client name pattern matching */
                /* return 2 if string matches fqdn TRUSTCLIENT pattern */
            } else if ((name != NULL) && (regexec(&patterns[i].regexv, name, 0, 0, 0) == 0)) {
                debugs(2, "DEBUG trustclient (%s) matched: %s\n", patterns[i].pattern, name);
                return 2;
            }
        } else if ((scan_mode == SCAN_NONE) && (patterns[i].type == UNTRUSTCLIENT)) {
            /* Look at client ip pattern matching */
            /* return 1 if string doesn't matches ip UNTRUSTCLIENT pattern */
            if (regexec(&patterns[i].regexv, ip, 0, 0, 0) != 0) {
                debugs(3, "DEBUG untrustclient (%s) not matched: %s\n", patterns[i].pattern, ip);
                return 1;
                /* Look at client name pattern matching */
                /* return 2 if string doesn't matches fqdn UNTRUSTCLIENT pattern */
            } else if ((name != NULL) && (regexec(&patterns[i].regexv, name, 0, 0, 0) != 0)) {
                debugs(3, "DEBUG untrustclient (%s) not matched: %s\n", patterns[i].pattern, name);
                return 2;
            }
        }
    }

    /* return 0 otherwise */
    return 0;
}

/* scconfig.c */

/* load the squidscas.conf */
int load_patterns() {
    FILE *fp = NULL;

    if (isPathExists(CONFIGDIR "/" CONFIG_FILE)) {
        return S_ERROR;
    }

    debugs(0, "LOG Reading configuration from %s\n", CONFIGDIR "/" CONFIG_FILE);
    fp = fopen(CONFIGDIR "/" CONFIG_FILE, "rt");
    if (fp == NULL) {
        debugs(0, "FATAL unable to open configuration file: %s\n", CONFIGDIR "/" CONFIG_FILE);
        return S_ERROR;
    }

    char buf[LINE_READ_BUFF];
    while ((fgets(buf, sizeof(buf), fp) != NULL)) {
        /* chop newline */
        chomp(buf);
        /* add to regex patterns array */
        if ((strlen(buf) > 0) && (add_pattern(buf, 0) != S_OK)) {
            debugs(0, "FATAL can't add pattern: %s\n", buf);
            fclose(fp);
            return S_ERROR;
        }
    }
    
    fclose(fp);

    if (!redirect_url[0]) {
        debugs(0, "FATAL you must set redirect_url or use c-icap 0.2.x or upper to use templates\n");
        return S_ERROR;
    }

    return S_OK;
}

int growPatternArray(SCPattern *item) {
    void * _tmp = NULL;
    if (pattc == current_pattern_size) {
        if (current_pattern_size == 0)
            current_pattern_size = PATTERN_ARR_SIZE;
        else
            current_pattern_size *= 2;

        _tmp = realloc(patterns, (current_pattern_size * sizeof(SCPattern)));
        if (!_tmp) {
            return -1;
        }

        patterns = (SCPattern *)_tmp;
    }
    patterns[pattc] = *item;
    pattc++;

    return pattc;
}

/* Add regexp expression to patterns array */
int add_pattern(char *s, int level) {
    char first[LOW_BUFF];
    char type[LOW_CHAR];
    int stored = 0;
    int regex_flags = REG_NOSUB;
    SCPattern currItem;
    char *end = NULL;
    int ret = S_OK;

    memset(&currItem, 0, sizeof(currItem));

    /* skip empty and commented lines */
    if ((xstrnlen(s, LOW_BUFF) == 0) || (strncmp(s, "#", 1) == 0)) {
        debugs(10, "DEBUG Comment line: %s\n", s);
        return S_OK;
    }

    /* Config file directives are construct as follow: name value */
    stored = sscanf(s, "%31s %255[^#]", type, first);
    if (stored < 2) {
        debugs(0, "FATAL Bad configuration line for [%s]\n", s);
        return S_ERROR;
    }

    /* remove extra space or tabulation */
    trim(first);

    debugs(5, "LOG Reading directive %s with value %s\n", type, first);
    /* URl to redirect Squid on virus found */
    if (strcmp(type, "redirect") == 0) {
        xstrncpy(redirect_url, first, sizeof(redirect_url));
        debugs(5, "DEBUG redirect_url: %s\n", redirect_url);
        
        return S_OK;
    }

    /* Path for file scan */
    if (strcmp(type, "scanpath") == 0) {
        if (isPathExists(first) == S_OK) {
            xstrncpy(scan_path, first, sizeof(scan_path));
            debugs(5, "DEBUG scan_path: %s\n", scan_path);
        } else {
            debugs(0, "LOG Wrong path to scanpath, disabling.\n");
        }
        
        return S_OK;
    }

    if (strcmp(type, "dnslookup") == 0) {
        if (dnslookup == 1) {
            dnslookup = atoi(first);
        }

        return S_OK;
    }

    if (strcmp(type, "timeout") == 0) {
        timeout = atoi(first);
        if (timeout > 10) {
            timeout = 10;
        }
        
        return S_OK;
    }

    if (strcmp(type, "stat") == 0) {
        statit = atoi(first);

        return S_OK;
    }

    if (strcmp(type, "maxsize") == 0) {
        maxsize = ci_strto_off_t(first, &end, 10);
        if ((maxsize == 0 && errno != 0) || maxsize < 0)
            maxsize = 0;
        if ( *end == 'k' || *end == 'K')
            maxsize = maxsize * 1024;
        else if ( *end == 'm' || *end == 'M')
            maxsize = maxsize * 1024 * 1024;
        else if ( *end == 'g' || *end == 'G')
            maxsize = maxsize * 1024 * 1024 * 1024;
        
        return S_OK;
    }

    /* Scan mode */
    if (strcmp(type, "scan_mode") == 0) {
        char scan_type[LOW_BUFF];
        memset(scan_type, 0, sizeof(scan_type));

        if (strncmp(first, "ScanNothingExcept", sizeof(first)) == 0) {
            scan_mode = SCAN_NONE;
            debugs(0, "LOG setting squidscas scan mode to 'ScanNothingExcept'.\n");
        } else if (strncmp(first, "ScanAllExcept", sizeof(first)) == 0) {
            scan_mode = SCAN_ALL;
            debugs(0, "LOG setting squidscas scan mode to 'ScanAllExcept'.\n");
        } else if (strlen(first) > 0) {
            fprintf(stderr, "incorrect value in scan_mode, failling back to ScanAllExcept mode.\n");
            scan_mode = SCAN_ALL;
        }
        
        return S_OK;
    }

    /* SECIOSS */
    if (strcmp(type, "memcached_servers") == 0) {
        char **argv = split(first, ' ');
        ret = mc_cfg_servers_set((const char **)argv);
        free(argv);

        return ret;
    }

    if (strcmp(type, "whitelist") == 0) {
        ret = scas_cfg_url_list_set(first, &whitelist);
        return ret;
    }

    if (strcmp(type, "blacklist") == 0) {
        ret = scas_cfg_url_list_set(first, &blacklist);
        return ret;
    }

    if (strcmp(type, "authz_api") == 0) {
        xstrncpy(authz_api, first, sizeof(authz_api));
        return S_OK;
    }

    if (strcmp(type, "authz_api_token") == 0) {
        xstrncpy(authz_api_token, first, sizeof(authz_api_token));
        return S_OK;
    }

    if (strcmp(type, "servicelist") == 0) {
        ret = scas_cfg_services_set(first);
        return ret;
    }

    if (strcmp(type, "viruslist") == 0) {
        ret = scas_cfg_virus_list_set(first);
        return ret;
    }

    if (strcmp(type, "mail_export_path") == 0) {
        xstrncpy(mail_export_path, first, sizeof(mail_export_path));
        return S_OK;
    }

    /* force case insensitive pattern matching */
    /* so aborti, contenti, regexi are now obsolete */
    regex_flags |= REG_ICASE;
    /* Add extended regex search */
    regex_flags |= REG_EXTENDED;

    /* Fill the pattern type */
    if (strcmp(type, "abort") == 0) {
        currItem.type = ABORT;
    } else if (strcmp(type, "abortcontent") == 0) {
        currItem.type = ABORTCONTENT;
    } else if (strcmp(type, "scan") == 0) {
        currItem.type = SCAN;
    } else if (strcmp(type, "scancontent") == 0) {
        currItem.type = SCANCONTENT;
    } else if (strcmp(type, "trustuser") == 0) {
        currItem.type = TRUSTUSER;
    } else if (strcmp(type, "trustclient") == 0) {
        currItem.type = TRUSTCLIENT;
    } else if (strcmp(type, "untrustuser") == 0) {
        currItem.type = UNTRUSTUSER;
    } else if (strcmp(type, "untrustclient") == 0) {
        currItem.type = UNTRUSTCLIENT;
    } else if ((strcmp(type, "squid_ip") != 0) && (strcmp(type, "squid_port") != 0) && (strcmp(type, "maxredir") != 0) && (strcmp(type, "useragent") != 0) && (strcmp(type, "trust_cache") != 0)) {
        fprintf(stderr, "WARNING Bad configuration keyword: %s\n", s);
        return S_ERROR;
    }

    /* Fill the pattern flag */
    currItem.flag = regex_flags;

    /* Fill pattern array */
    xstrncpy(currItem.pattern, first, sizeof(currItem.pattern));
    if (regcomp(&currItem.regexv, currItem.pattern, currItem.flag) != 0) {
        debugs(0, "ERROR Invalid regex pattern: %s\n", currItem.pattern);
    } else {
        if (growPatternArray(&currItem) < 0) {
            fprintf(stderr, "unable to allocate new pattern in add_to_patterns()\n");
            return S_ERROR;
        }
    }

    return S_OK;
}

/* return 1 when the file have some regex content, 0 otherwise */
int readFileContent(char *filepath, char *kind) {
    FILE *fp = NULL;

    if (isFileExists(filepath) != S_OK) {
        return S_ERROR;
    }

    debugs(5, "LOG Reading %s information from file from %s\n", kind, filepath);
    fp = fopen(filepath, "rt");
    if (fp == NULL) {
        debugs(0, "FATAL unable to open %s file: %s\n", kind, filepath);
        return S_ERROR;
    }
    
    char buf[LINE_READ_BUFF];
    while ((fgets(buf, sizeof(buf), fp) != NULL)) {
        /* chop newline */
        chomp(buf);

        /* add to regex patterns array */
        char str[LOW_BUFF + LOW_CHAR + 1];
        snprintf(str, sizeof(str), "%s %s", kind, buf);
        if ((strlen(buf) > 0) && (add_pattern(str, 1) != S_OK)) {
            debugs(0, "FATAL can't add pattern: %s\n", buf);
            fclose(fp);
            return S_ERROR;
        }
    }

    fclose(fp);

    return S_OK;
}

int extract_http_info(ci_request_t *req, ci_headers_list_t *req_header, struct http_info *httpinf) {
    /* Format of the HTTP header we want to parse:
       GET http://www.squid-cache.org/Doc/config/icap_service HTTP/1.1
       */
    memset(httpinf->url, 0, sizeof(httpinf->url));
    memset(httpinf->method, 0, sizeof(httpinf->method));

    char **splited = split(req_header->headers[0], ' ');
    xstrncpy(httpinf->method, splited[0], sizeof(httpinf->method));
    debugs(10, "DEBUG method %s\n", httpinf->method);

    if (!splited[1]) {
        debugs(2, "WARNING Invalied header %s\n", req_header->headers[0]);
        free(splited);
        return S_ERROR;
    }

    xstrncpy(httpinf->url, splited[1], sizeof(httpinf->url));
    debugs(10, "DEBUG url %s\n", httpinf->url);

    if (strstr(splited[2], "HTTP/") == NULL) {
        debugs(2, "WARNING Invalied http version %s\n", req_header->headers[0]);
        free(splited);
        return S_ERROR;
    }
    
    free(splited);

    return S_OK;
}

const char *http_content_type(ci_request_t *req) {
    ci_headers_list_t *heads;
    const char *val;
    if (!(heads = ci_http_response_headers(req))) {
        /* Then maybe is a reqmod request, try to get request headers */
        if (!(heads = ci_http_request_headers(req)))
            return NULL;
    }
    if (!(val = ci_headers_value(heads, "Content-Type")))
        return NULL;

    return val;
}

void free_global() {
    pthread_mutex_lock(&MUTEX);

    if (patterns) {
        debugs(9, " DEBUG clean patterns %p\n", patterns);
        while (pattc > 0) {
            pattc--;
            regfree(&patterns[pattc].regexv);
        }
        free(patterns);
        patterns = NULL;
    }
    if (MC) {
        debugs(9, " DEBUG clean memcached_free %p\n", &MC);
        memcached_pool_destroy(MC_POOL);
        memcached_free(MC);
        MC = NULL;
    }
    if (mamcache_servers_list) {
        debugs(9, " DEBUG clean mamcache_servers_list %p\n", mamcache_servers_list);
        ci_list_destroy(mamcache_servers_list);
        mamcache_servers_list = NULL;
    }
    if (whitelist) {
        debugs(9, " DEBUG clean whitelist %p\n", whitelist);
        ci_list_destroy(whitelist);
        whitelist = NULL;
    }
    if (blacklist) {
        debugs(9, " DEBUG clean blacklist %p\n", blacklist);
        ci_list_destroy(blacklist);
        blacklist = NULL;
    }
    if (services_list) {
        debugs(9, " DEBUG clean services_list %p\n", services_list);
        ci_list_destroy(services_list);
        services_list = NULL;
    }
    if (virus_list) {
        debugs(9, " DEBUG clean virus_list %p\n", virus_list);
        ci_list_destroy(virus_list);
        virus_list = NULL;
    }
    
    pthread_mutex_unlock(&MUTEX);
}

static const char *blocked_header_message =
    "<html>\n"
    "<body>\n"
    "<p>\n"
    "You will be redirected in few seconds, if not use this <a href=\"";

static const char *blocked_footer_message =
    "\">direct link</a>.\n"
    "</p>\n"
    "</body>\n"
    "</html>\n";

void generate_response_page(ci_request_t *req, scas_req_data_t *data) {
    if (redirect_url[0]) {
        int msg_code;
        char urlredir[MAX_URL];
        memset(urlredir, 0, sizeof(urlredir));

        if (data->virus) {
            snprintf(urlredir, sizeof(urlredir), "%s?msg=auth_err_101", redirect_url);
        } else {
            switch (data->code) {
            case 8:
                msg_code = 3;
                break;
            case 7:
                msg_code = 1;
                break;
            case 6:
                msg_code = 9;
                break;
            case 5:
                msg_code = 8;
                break;
            case 4:
                msg_code = 7;
                break;
            case 3:
                msg_code = 6;
                break;
            case 2:
                msg_code = 2;
                break;
            case 1:
                msg_code = 1;
                break;
            default:
                msg_code = 5;
                break;
            }
            snprintf(urlredir, sizeof(urlredir), "%s?msg=auth_err_%03d", redirect_url, msg_code);
        }
        generate_redirect_page(urlredir, req, data);
    }
}

void generate_redirect_page(char *redirect, ci_request_t *req, scas_req_data_t *data) {
    int new_size = 0;
    char buf[MAX_URL];
    ci_membuf_t *error_page;

    new_size = strlen(blocked_header_message) + strlen(redirect) + strlen(blocked_footer_message) + 10;

    if (ci_http_response_headers(req))
        ci_http_response_reset_headers(req);
    else
        ci_http_response_create(req, 1, 1);

    debugs(2, "DEBUG creating redirection page\n");

    snprintf(buf, sizeof(buf), "Location: %s", redirect);
    /*strcat(buf, ";");*/

    debugs(3, "DEBUG refirect %s\n", buf);

    ci_http_response_add_header(req, "HTTP/1.0 307 Temporary Redirect");
    ci_http_response_add_header(req, buf);
    ci_http_response_add_header(req, "Server: C-ICAP");
    ci_http_response_add_header(req, "Connection: close");
    ci_http_response_add_header(req, "Content-Type: text/html");
    ci_http_response_add_header(req, "Content-Language: en");
    ci_icap_add_xheader(req, buf);
    ci_http_response_add_header(req, buf);
    ci_icap_add_xheader(req, buf);
    ci_http_response_add_header(req, buf);

    if (data->blocked == 1) {
        error_page = ci_membuf_new_sized(new_size);
        ((scas_req_data_t *)data) -> error_page = error_page;
        ci_membuf_write(error_page, (char * ) blocked_header_message, strlen(blocked_header_message), 0);
        ci_membuf_write(error_page, (char * ) redirect, strlen(redirect), 0);
        ci_membuf_write(error_page, (char * ) blocked_footer_message, strlen(blocked_footer_message), 1);
    }
    debugs(3, "DEBUG done\n");
}

/* SECIOSS */

ci_headers_list_t *get_headers_from_entities(ci_encaps_entity_t **entities, int type) {
    ci_encaps_entity_t *e;
    while ((e = *entities++) != NULL) {
        if (e->type == type)
            return (ci_headers_list_t *)(e->entity);
    }
    return NULL;
}

size_t authz_writer(char *ptr, size_t size, size_t nmemb, void *stream) {
    struct Buffer *buf = (struct Buffer *)stream;
    int block = size * nmemb;

    buf->data = (char *)malloc(block);
    if (buf->data == NULL) {
        debugs(1, "Error allocating memory for buffer\n");
        return block;
    }

    memcpy(buf->data, ptr, block);
    buf->data[block] = '\0';
    buf->size = block;

    return block;
}

char *authorization(const char *action, const char *username, const char *clientip, const char *user_agent) {
    CURL *curl;
    CURLcode rc;
    struct curl_slist *headers = NULL;
    struct Buffer write_data;
    char rbuf[SMALL_BUFF];
    char authz_header[MAX_TOKEN];
    char *escaped_agent;
    char *data = NULL;

    memset(&write_data, 0, sizeof(write_data));

    curl = curl_easy_init();
    if (curl == NULL) {
        return NULL;
    }

    if (!strcmp(action, "acl")) {
        sprintf(rbuf, "action=acl&id=%s", username);
    } else {
        escaped_agent = curl_easy_escape(curl, user_agent, 0);
        sprintf(rbuf, "action=token&id=%s&ip=%s&agent=%s", username, clientip, escaped_agent);
        curl_free(escaped_agent);
    }

    curl_easy_setopt(curl, CURLOPT_URL, authz_api);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, rbuf);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(rbuf));
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, authz_writer);
    if (authz_api_token[0]) {
        snprintf(authz_header, sizeof(authz_header), "Authorization: Bearer %s", authz_api_token);
        headers = curl_slist_append(headers, authz_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    debugs(5, "DEBUG Request: %s\n", authz_api);
    debugs(5, "DEBUG POST DATA: %s\n", rbuf);
    rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (headers != NULL) {
        curl_slist_free_all(headers);
    }
    debugs(5, "DEBUG Response: %s\n", write_data.data);

    data = write_data.data;

    if (rc != CURLE_OK) {
        return NULL;
    }

    return data;
}

int mc_cfg_servers_set(const char **argv) {
    int argc;

    if (!mamcache_servers_list) {
        mamcache_servers_list = ci_list_create(INIT_LIST_SIZE * sizeof(mc_server_t), sizeof(mc_server_t));
        if (!mamcache_servers_list) {
            debugs(1, "Error allocating memory for mc_servers list!\n");
            return S_ERROR;
        }
    }

    for (argc = 0; argv[argc] != NULL; argc++) {
        mc_server_t srv;
        memset(&srv, 0, sizeof(srv));
        
        xstrncpy(srv.hostname, argv[argc], sizeof(srv.hostname));
        char *s = NULL;
        if (srv.hostname[0] != '/' && (s = strchr(srv.hostname, ':')) != NULL) {
            *s = '\0';
            s++;
            srv.port = atoi(s);
            if (!srv.port) {
                srv.port = 11211;
            }
        } else {
            srv.port = 11211;
        }
        debugs(0, "LOG Setup memcached server %s:%d\n", srv.hostname, srv.port);
        
        if (!ci_list_push_back(mamcache_servers_list, &srv)) {
            debugs(0, "FATAL mamcache_servers list push back failed\n");
            return S_ERROR;
        }
    }

    return S_OK;
}

int scas_cfg_url_list_set(const char *filepath, ci_list_t **url_list) {
    FILE *fp = NULL;

    if (isFileExists(filepath) != 0) {
        debugs(1, "Error file not found: %s\n", filepath);
        return S_ERROR;
    }

    *url_list = ci_list_create(INIT_LIST_SIZE * sizeof(scas_url_t), sizeof(scas_url_t));
    if (!*url_list) {
        debugs(1, "Error allocating memory for url list!\n");
        return S_ERROR;
    }

    debugs(5, "LOG Reading information from file from %s\n", filepath);
    fp = fopen(filepath, "rt");
    if (fp == NULL) {
        debugs(0, "FATAL unable to open file: %s\n", filepath);
        return S_ERROR;
    }

    char buf[LINE_READ_BUFF];
    while ((fgets(buf, sizeof(buf), fp) != NULL)) {
        /* chop newline */
        chomp(buf);
        if (strlen(buf) > 0) {
            scas_url_t url;
            memset(&url, 0, sizeof(url));
            xstrncpy(url.url, buf, sizeof(url.url));
            if (!ci_list_push_back(*url_list, &url)) {
                debugs(0, "FATAL url list push back failed\n");
                return S_ERROR;
            }
        }
    }
    
    fclose(fp);

    return S_OK;
}

int scas_cfg_services_set(const char *filepath) {
    int ret = S_OK;

    if (isFileExists(filepath) != 0) {
        debugs(1, "Error file not found: %s\n", filepath);
        return S_ERROR;
    }

    if (!services_list) {
        services_list = ci_list_create(INIT_LIST_SIZE * sizeof(scas_service_t), sizeof(scas_service_t));
        if (!services_list) {
            debugs(1, "Error allocating memory for scas_services list!\n");
            return S_ERROR;
        }
    }

    debugs(0, "LOG Reading information from file from %s\n", filepath);
    FILE *fp = fopen(filepath, "rt");
    if (fp == NULL) {
        debugs(0, "FATAL unable to open file: %s\n", filepath);
        return S_ERROR;
    }

    char buf[LINE_READ_BUFF];
    while ((fgets(buf, sizeof(buf), fp) != NULL)) {
        /* chop newline */
        chomp(buf);
        if (strlen(buf) <= 0) {
            continue; 
        }

        scas_service_t service;
        memset(&service, 0, sizeof(service));

        char *urls = NULL;
        char *login = NULL;
        char *updates = NULL;
        char *share = NULL;

        // 0: サービスID
        // 1: urls
        // 2: login
        // 3: updates
        // 4: share
        char** service_items = split(buf, '\t');
        xstrncpy(service.id, service_items[0], sizeof(service.id));
        urls = service_items[1];
        if (!urls) {
            debugs(0, "FATAL invalid service format: %s\n", service.id);
            ret = S_ERROR;
            free(service_items);
            break;
        }
        login = service_items[2];
        if (login) {
            updates = service_items[3];
            if (updates) {
                share = service_items[4];
            }
        }
        debugs(10, "DEBUG service.id: '%s'\n", service.id);
        debugs(10, "DEBUG urls: '%s'\n", urls);
        debugs(10, "DEBUG login: '%s'\n", login);
        debugs(10, "DEBUG updates: '%s'\n", updates);
        debugs(10, "DEBUG share: '%s'\n", share);
        
        int i=0;
        for (char **s = split(urls, ';'); *s !=NULL && i<NUM_OF_URLS; s++) {
            xstrncpy(service.urls[i], *s, sizeof(service.urls[i]));
            i++;
        }

        if (login && login[0] && strcmp(login, " ")) {
            char** s = split(login, '#');
            xstrncpy(service.login_url, s[0], sizeof(service.login_url));
            if (s[1] == NULL) {
                debugs(0, "FATAL invalid login format: %s\n", service.id);
                ret = S_ERROR;
            } else if (regcomp(&service.login_regexv, s[1], REG_EXTENDED)) {
                debugs(0, "FATAL login regex comple failed: %s\n", s[1]);
                ret = S_ERROR;
            }
            free(s);
        }

        if (updates && updates[0] && strcmp(updates, " ")) {
            char **elts = split(updates, ';');
            for (int i=0; i<NUM_OF_URLS; i++) {
                if (elts[i] == NULL) {
                    break;
                }
                
                char** s = split(elts[i], '#');
                xstrncpy(service.update_urls[i], s[0], sizeof(service.update_urls[i]));
                if (s[0]) {
                    xstrncpy(service.update_params[i], s[1], sizeof(service.update_params[i]));
                }
                free(s);
            }
            free(elts);
        }

        if (share && share[0] && strcmp(share, " ")) {
            char **s = split(share, '#');
            if (regcomp(&service.share_url, s[0], REG_EXTENDED | REG_NOSUB)) {
                debugs(0, "FATAL share url comple failed: %s\n", s[0]);
                ret = S_ERROR;
            } else if (s[1] == NULL) {
                debugs(0, "FATAL invalid share format: %s\n", service.id);
                ret = S_ERROR;
            } else if (regcomp(&service.share_regexv, s[1], REG_EXTENDED)) {
                debugs(0, "FATAL share regex comple failed: %s\n", s[1]);
                ret = S_ERROR;
            } else {
                service.share = 1;
            }
            free(s);
        }

        debugs(10, "DEBUG service.id: %s\n", service.id);
        for (char **s=service.urls; *s; s++) {
            debugs(10, "DEBUG service.urls: %s\n", s);
        }
        debugs(10, "DEBUG service.login_url: %s\n", service.login_url);
        for (int i=0; i<NUM_OF_URLS && service.update_urls[i][0]; i++) {
            debugs(10, "DEBUG service.update_urls: %s\n", service.update_urls[i]);
            debugs(10, "DEBUG service.update_params: %s\n", service.update_params[i]);
        }
        debugs(10, "DEBUG service.share: %d\n", service.share);

        if (!ci_list_push_back(services_list, &service)) {
            debugs(0, "FATAL service list push back failed\n");
            return S_ERROR;
        }
        free(service_items);
    }

    fclose(fp);

    return ret;
}

int scas_cfg_virus_list_set(const char *filepath) {
    FILE *fp = NULL;

    if (isFileExists(filepath) != S_OK) {
        debugs(1, "Error file not found: %s\n", filepath);
        return S_ERROR;
    }

    if (!virus_list) {
        virus_list = ci_list_create(INIT_LIST_SIZE * sizeof(scas_virus_t), sizeof(scas_virus_t));
        if (!virus_list) {
            debugs(1, "Error allocating memory for virus list!\n");
            return S_ERROR;
        }
    }

    debugs(5, "LOG Reading information from file from %s\n", filepath);
    fp = fopen(filepath, "rt");
    if (fp == NULL) {
        debugs(0, "FATAL unable to open file: %s\n", filepath);
        return S_ERROR;
    }

    char buf[LINE_READ_BUFF];
    while ((fgets(buf, sizeof(buf), fp) != NULL)) {
        /* chop newline */
        chomp(buf);
        if (strlen(buf) > 0) {
            scas_virus_t virus;
            memset(&virus, 0, sizeof(virus));

            char **sprited = split(buf, ',');
            xstrncpy(virus.id, sprited[0], sizeof(virus.id));
            if (sprited[1]) {
                xstrncpy(virus.checksum, sprited[1], sizeof(virus.checksum));
                if (!ci_list_push_back(virus_list, &virus)) {
                    debugs(0, "FATAL virus list push back failed\n");
                    return S_ERROR;
                }
            }
            free(sprited);
        }
    }
    
    fclose(fp);

    return S_OK;
}

