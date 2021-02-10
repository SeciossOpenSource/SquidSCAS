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
#include <libmemcached/memcached.h>
#include <magic.h>
#include <openssl/sha.h>

typedef struct scas_service {
    char id[256];
    char **urls;
    char *login_url;
    regex_t login_regexv;
    char *update_urls[10];
    char *update_params[10];
    int share;
    regex_t share_url;
    regex_t share_regexv;
} scas_service_t;

/* Structure used to store information passed throught the module methods */
typedef struct scas_req_data {
    ci_simple_file_t *body;
    ci_request_t *req;
    ci_membuf_t *error_page;
    const scas_service_t * service;
    int blocked;
    int no_more_scan;
    int virus;
    char *url;
    char *user;
    char *clientip;
    char *operation;
    char *allowed;
    char *share_user;
} scas_req_data_t;

static int SEND_PERCENT_BYTES = 0;
static ci_off_t START_SEND_AFTER = 1;

/*squidscas service extra data ... */
ci_service_xdata_t *squidscas_xdata = NULL;

int AVREQDATA_POOL = -1;

/* SECIOSS */
#define MC_DOMAINLEN 32
#define MC_MAXKEYLEN 250
#define MAGIC_HEADER_SIZE (16 * 1024)
#define HOSTNAME_LEN 256
#define ID_LEN 256
typedef struct mc_server {
    char hostname[HOSTNAME_LEN];
    int port;
} mc_server_t;

typedef struct scas_virus {
    char id[ID_LEN];
    char checksum[LOW_BUFF];
} scas_virus_t;

static ci_list_t *servers_list = NULL;
static ci_list_t *services_list = NULL;
static ci_list_t *virus_list = NULL;

memcached_st *MC = NULL;

int squidscas_init_service(ci_service_xdata_t * srv_xdata, struct ci_server_conf *server_conf);
int squidscas_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t *);
int squidscas_end_of_data_handler(ci_request_t *);
void *squidscas_init_request_data(ci_request_t * req);
void squidscas_close_service();
void squidscas_release_request_data(void *data);
int squidscas_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t * req);
int squidscas_post_init_service(ci_service_xdata_t * srv_xdata, struct ci_server_conf *server_conf);

/* General functions */
void set_istag(ci_service_xdata_t * srv_xdata);
const char *get_filename_ext(const char *filename);
int copy_file(int ptr_old, const char  *new_filename);
int has_invalid_chars(const char *inv_chars, const char *target);

/* SECIOSS */
ci_headers_list_t* get_headers_from_entities(ci_encaps_entity_t** entities, int type);
int mimetype(int fd_src, char *mime);
char* tolowerstring(char *str);
int sha1sum(int fd_src, char *checksum);
int urldecode(const char *s, char *dec);
int mc_cfg_servers_set(const char **argv);
int scas_cfg_services_set(const char *filepath);
int scas_cfg_virus_list_set(const char *filepath);

/* Declare SeciossCAS C-ICAP service */
CI_DECLARE_MOD_DATA ci_service_module_t service = {
    "squidscas",                    /*Module name */
    "SeciossCAS/CASB service", /* Module short description */
    ICAP_RESPMOD | ICAP_REQMOD,      /* Service type modification */
    squidscas_init_service,          /* init_service. */
    squidscas_post_init_service,     /* post_init_service. */
    squidscas_close_service,         /* close_service */
    squidscas_init_request_data,     /* init_request_data. */
    squidscas_release_request_data,  /* release request data */
    squidscas_check_preview_handler, /* Preview data */
    squidscas_end_of_data_handler,   /* when all data has been received */
    squidscas_io,
    NULL,
    NULL
};

int statit = 0;
int timeout = 1;
char *redirect_url = NULL;
char *clamd_local = NULL;
char *clamd_ip = NULL;
char *clamd_port = NULL;
char *clamd_curr_ip = NULL;
SCPattern *patterns = NULL;
int pattc = 0;
int current_pattern_size = 0;
ci_off_t maxsize = 0;
int dnslookup = 1;
/* Default scan mode ScanAllExcept */
int scan_mode = 1;
char *scan_path = NULL;

/* Used by pipe to squidGuard */
int usepipe = 0;
pid_t pid;
FILE *sgfpw = NULL;
FILE *sgfpr = NULL;


/* --------------- URL CHECK --------------------------- */

struct http_info {
    char method[MAX_METHOD_SIZE];
    char url[MAX_URL];
};

int extract_http_info(ci_request_t *, ci_headers_list_t *, struct http_info *);
const char *http_content_type(ci_request_t *);
void free_global ();
void generate_redirect_page(char *, ci_request_t *, scas_req_data_t *);
void generate_response_page(ci_request_t *, scas_req_data_t *);
#ifdef HAVE_CICAP_TEMPLATE
void cfgreload_command(const char *name, int type, const char **argv);
#else
void cfgreload_command(char *name, int type, char **argv);
#endif
char * replace(const char *s, const char *old, const char *new);

/* ----------------------------------------------------- */

/* Sends bytes over a socket. Returns the number of bytes sent */
int sendln(int asockd, const char *line, unsigned int len)
{
    int bytesent = 0;
    while (len) {
        int sent = send(asockd, line, len, 0);
        if (sent <= 0) {
            if(sent && errno == EINTR) continue;
            debugs(0, "ERROR Can't send to clamd: %s\n", strerror(errno));
            return sent;
        }
        line += sent;
        len -= sent;
        bytesent += sent;
    }
    return bytesent;
}

int squidscas_init_service(ci_service_xdata_t * srv_xdata,
                             struct ci_server_conf *server_conf)
{
    unsigned int xops;

    debugs(2, "DEBUG Going to initialize squidscas\n");

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

    if(AVREQDATA_POOL < 0) {
        debugs(0, "FATAL error registering object_pool scas_req_data_t\n");
        return CI_ERROR;
    }

    /* Reload configuration command */
    register_command("squidscas:cfgreload", MONITOR_PROC_CMD | CHILDS_PROC_CMD, cfgreload_command);


    /* allocate memory for some global variables */
    clamd_curr_ip = (char *) malloc (sizeof (char) * SMALL_CHAR);
    memset(clamd_curr_ip, 0, sizeof (char) * SMALL_CHAR);

    /*********************
      read config files
     ********************/
    if (load_patterns() == 0) {
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

    /* reallocate memory for some global variables removed in free_global() */
    clamd_curr_ip = (char *) malloc (sizeof (char) * SMALL_CHAR);
    memset(clamd_curr_ip, 0, sizeof (char) * SMALL_CHAR);

    /* read configuration file */
    if (load_patterns() == 0)
        debugs(0, "FATAL reload configuration command failed!\n");
    if (squidscas_xdata)
        set_istag(squidscas_xdata);

}

int squidscas_post_init_service(ci_service_xdata_t * srv_xdata,
                                  struct ci_server_conf *server_conf)
{
    /* SECIOSS */
    const mc_server_t *srv;
    const char *default_servers[] = {
        "127.0.0.1",
        NULL
    };

    if (servers_list == NULL) {
        mc_cfg_servers_set(default_servers);
        if (servers_list == NULL)
            return CI_ERROR;
    }

    MC = memcached_create(NULL);
    if (MC == NULL) {
        debugs(0, "FATAL Failed to create memcached instance\n");
        return CI_ERROR;
    }

    for (srv = (const mc_server_t *)ci_list_first(servers_list); srv != NULL ; srv = (const mc_server_t *)ci_list_next(servers_list)) {
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

    return CI_OK;
}

void squidscas_close_service()
{
    debugs(2, "DEBUG clean all memory!\n");
    free_global();
    ci_object_pool_unregister(AVREQDATA_POOL);
}

void *squidscas_init_request_data(ci_request_t * req)
{
    scas_req_data_t *data;

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


void squidscas_release_request_data(void *data)
{

    if (data)
    {
        debugs(2, "DEBUG Releasing request data.\n");

        if (((scas_req_data_t *) data)->body)
            ci_simple_file_destroy(((scas_req_data_t *) data)->body);
        if (((scas_req_data_t *) data)->url)
            ci_buffer_free(((scas_req_data_t *) data)->url);
        if (((scas_req_data_t *) data)->user)
            ci_buffer_free(((scas_req_data_t *) data)->user);
        if (((scas_req_data_t *) data)->clientip)
            ci_buffer_free(((scas_req_data_t *) data)->clientip);
        if (((scas_req_data_t *) data)->error_page)
            ci_membuf_free(((scas_req_data_t *) data)->error_page);
        if (((scas_req_data_t *) data)->operation)
            ci_buffer_free(((scas_req_data_t *) data)->operation);
        if (((scas_req_data_t *) data)->allowed)
            ci_buffer_free(((scas_req_data_t *) data)->allowed);
        if (((scas_req_data_t *) data)->share_user)
            ci_buffer_free(((scas_req_data_t *) data)->share_user);

        ci_object_pool_free(data);
    }
}

int squidscas_check_preview_handler(char *preview_data, int preview_data_len,
                                      ci_request_t * req)
{
    ci_headers_list_t *req_header;
    struct http_info httpinf;
    scas_req_data_t *data = ci_service_data(req);
    const char *clientip;
    struct hostent *clientname;
    unsigned long ip;
    const char *username;
    int chkipdone = 0;

    debugs(2, "DEBUG processing preview header.\n");

    if (preview_data_len) {
        debugs(2, "DEBUG preview data size is %d\n", preview_data_len);
    }

    /* Extract the HTTP header from the request */
    if ((req_header = ci_http_request_headers(req)) != NULL) {
	    int scanit = scan_mode == SCAN_ALL ? 1 : 0;
	    int content_length = 0;
	    const char *content_type = NULL;
            const char *content_disposition = NULL;
            char *file_extension = NULL;
            ci_headers_list_t *eh = NULL;
            const char *user_agent = NULL;
            const scas_service_t *service;
            const char *service_id = NULL;
            char **tokens;
            char operation[20] = "view";
            memcached_return rc;
            uint32_t flags;
            char key[1024];
            char mckey[MC_MAXKEYLEN+1];
            int mckeylen = 0;
            char *value;
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
		    if ( (clientname = gethostbyaddr((char *)&ip, sizeof(ip), AF_INET)) != NULL) {
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

            if ((eh = get_headers_from_entities(req->entities, ICAP_REQ_HDR)) == NULL) {
                debugs(1, "ERROR request headers in entities is null\n");
                return CI_MOD_ERROR;
            }

            /* Get the user agent */
            if ((user_agent = ci_headers_value(eh, "User-Agent")) != NULL) {
                debugs(2, "DEBUG User-Agent: %s\n", user_agent);
            }

	    /* Get the requested URL */
	    if (!extract_http_info(req, req_header, &httpinf)) {
		/* Something wrong in the header or unknow method */
		debugs(1, "ERROR bad http header, aborting.\n");
		return CI_MOD_ERROR;
	    }

	    debugs(2, "DEBUG URL requested: %s\n", httpinf.url);

	    /* CONNECT (https) and OPTIONS methods can not be scanned so abort */
	    if ( (strcmp(httpinf.method, "CONNECT") == 0) || (strcmp(httpinf.method, "OPTIONS") == 0) ) {
		debugs(2, "DEBUG method %s can't be scanned.\n", httpinf.method);
		return CI_MOD_ALLOW204;
	    }

	    if (scan_mode == SCAN_ALL) {
	        /* Check the URL against SeciossCAS Whitelist */
	        if (simple_pattern_compare(httpinf.url, WHITELIST) == 1) {
		    debugs(2, "DEBUG No antivir check (WHITELIST match) for url: %s\n", httpinf.url);
		    scanit = 0;
	        }
	    } else {
	        /* Check the URL against SeciossCAS blacklist */
	        if (simple_pattern_compare(httpinf.url, BLACKLIST) == 1) {
		    debugs(2, "DEBUG antivir check (BLACKLIST match) for url: %s\n", httpinf.url);
		    scanit = 1;
	        }
	    }

	    if (scan_mode == SCAN_ALL) {
	        /* Check the URL against SeciossCAS abort */
	        if (simple_pattern_compare(httpinf.url, ABORT) == 1) {
		    debugs(2, "DEBUG No antivir check (ABORT match) for url: %s\n", httpinf.url);
		    scanit = 0;
	        }
	    } else {
	        /* Check the URL against SeciossCAS scan */
	        if (simple_pattern_compare(httpinf.url, SCAN) == 1) {
		    debugs(2, "DEBUG antivir check (SCAN match) for url: %s\n", httpinf.url);
		    scanit = 1;
	        }
	    }

	    /* Get the content type header */
	    if ((content_type = http_content_type(req)) != NULL) {
                while(*content_type == ' ' || *content_type == '\t') content_type++;
		debugs(2, "DEBUG Content-Type: %s\n", content_type);
		if (scan_mode == SCAN_ALL) {
		    /* Check the Content-Type against SeciossCAS abortcontent */
		    if (simple_pattern_compare(content_type, ABORTCONTENT)) {
		        debugs(2, "DEBUG No antivir check (ABORTCONTENT match) for content-type: %s\n", content_type);
		        scanit = 0;
		    }
		} else {
		    /* Check the Content-Type against SeciossCAS scancontent */
		    if (simple_pattern_compare(content_type, SCANCONTENT)) {
		        debugs(2, "DEBUG No antivir check (SCANCONTENT match) for content-type: %s\n", content_type);
		        scanit = 1;
		    }
		}
	    }

            for (service = (const scas_service_t *)ci_list_first(services_list); service != NULL ; service = (const scas_service_t *)ci_list_next(services_list)) {
                for (i = 0; service->urls[i] != NULL; i++) {
                    if (strstr(httpinf.url, service->urls[i]) != NULL) {
                        service_id = service->id;
                        data->service = service;
                        break;
                    }
                }
                if (service_id) {
                    break;
                }
            }

            if (strcmp(httpinf.method, "GET") == 0) {
                eh = get_headers_from_entities(req->entities, ICAP_RES_HDR);
                if (eh) {
                    if ((content_disposition = ci_headers_value(eh, "Content-Disposition")) != NULL && (strstr(content_disposition, "filename=\"") != NULL || ci_headers_value(eh, "Etag"))) {
                        debugs(2, "DEBUG Content-Disposition: %s\n", content_disposition);
                        strcpy(operation, "download");
                    }
                    for (i = 0; i < eh->used; i++) {
                        debugs(3, "DEBUG Header %s\n", eh->headers[i]);
                    }
                }
            } else if (strcmp(httpinf.method, "POST") == 0 || strcmp(httpinf.method, "PUT") == 0) {
                char *s1 = NULL;
                char *s2 = NULL;
                char *tmp = NULL;

                content_disposition = ci_headers_value(eh, "Content-Disposition");
                if (content_disposition || (content_type && strncmp(content_type, "multipart/", 10) == 0 && strstr(content_type, "boundary=batch_") == NULL)) {
                    strcpy(operation, "upload");
                }
                if (content_disposition) {
                    debugs(2, "DEBUG Content-Disposition: %s\n", content_disposition);
                } else if (service_id) {
                    for (i = 0; i < eh->used; i++) {
                        debugs(3, "DEBUG Header %s\n", eh->headers[i]);
                        if (strcmp(service_id, "storage/office365_drive") == 0 && strcmp(eh->headers[i], "Scenario: UploadFile") == 0) {
                            // OneDrive
                            strcpy(operation, "upload");
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
                        } else if (strcmp(service_id, "iaas/aws") == 0 && ci_headers_value(eh, "Content-MD5")) {
                            // AWS S3
                            strcpy(operation, "upload");
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
                            strcpy(operation, "upload");
                            break;
                        }
                    }
                    if (s1 && s2) {
                        file_extension = malloc(s2 - s1 + 3);
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
                char *s1 = NULL;
                char *s2 = NULL;
                char **elts = NULL;
                regmatch_t *match_buf;
                size_t size;
                char allowed[20] = "";
                int personal = 0;
                int forbidden = -1;
                int match;
                char **user_values;
                char *loginid = NULL;
                char *login_domain = NULL;
                char *share_user = NULL;

                debugs(2, "DEBUG service id requested: %s\n", service_id);

                if (user_agent == NULL) {
                    debugs(1, "ERROR user_agent is null in %s\n", httpinf.url);
                    return CI_MOD_ERROR;
                }

                if (service->update_urls[0] && (strcmp(httpinf.method, "POST") == 0 || strcmp(httpinf.method, "PUT") == 0 || strcmp(httpinf.method, "DELETE") == 0)) {
                    for (i = 0; service->update_urls[i] != NULL; i++) {
                        if (strstr(httpinf.url, service->update_urls[i]) != NULL) {
                            if (service->update_params[i]) {
                                strcpy(operation, "is_update");
                            } else {
                                strcpy(operation, "update");
                            }
                        }
                    }
                }

                if (service->share && (strcmp(httpinf.method, "POST") == 0 || strcmp(httpinf.method, "PUT") == 0) && regexec(&service->share_url, httpinf.url, 0, NULL, 0) == 0) {
                    if (!strcmp(operation, "update") || !strcmp(operation, "is_update")) {
                        strcpy(operation, "update_share");
                    } else {
                        strcpy(operation, "share");
                    }
                }

                if ((s1 = strchr(username, (int)'@')) != NULL) {
                    mckeylen = sprintf(mckey, "secioss_cas:service_acl_%s", s1 + 1);
                } else {
                    mckeylen = sprintf(mckey, "secioss_cas:secioss_acl");
                }
                value = memcached_get(MC, mckey, mckeylen, &value_len, &flags, &rc);
                if (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND) {
                    debugs(1, "ERROR Failed to retrieve %s object from cache: %s\n", mckey, memcached_strerror(MC, rc));
                    return CI_MOD_ERROR;
                }
                if (value) {
                    sprintf(buf, "%s:", service_id);
                    if (strstr(value, buf) != NULL) {
                        no_acl = 0;
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
                                if (*(s2 - i) == '.') {
                                    s1 = s2 - i;
                                    break;
                                }
                            }
                            if (i > 0) {
                                file_extension = malloc(i + 2);
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
                    SHA1_Init(&sha1);
                    SHA1_Update(&sha1, (const unsigned char *)key, strlen(key));
                    SHA1_Final(digest, &sha1);
                    mckeylen = sprintf(mckey, "secioss_cas:%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                                   digest[0], digest[1], digest[2], digest[3],
                                   digest[4], digest[5], digest[6], digest[7],
                                   digest[8], digest[9], digest[10], digest[11],
                                   digest[12], digest[13], digest[14], digest[15],
                                   digest[16], digest[17], digest[18], digest[19]);
                    value = memcached_get(MC, mckey, mckeylen, &value_len, &flags, &rc);
                    if (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND) {
                        debugs(1, "ERROR Failed to retrieve %s(%s %s %s) object from cache: %s\n", mckey, username, clientip, user_agent, memcached_strerror(MC, rc));
                        return CI_MOD_ERROR;
                    }
                    if (value) {
                        debugs(2, "DEBUG tokens(%s %s %s) is %s\n", username, clientip, user_agent, value);

                        elts = split(value, "#");
                        if (service->login_url && strcmp(httpinf.method, "POST") == 0 && strstr(httpinf.url, service->login_url) != NULL) {
                            size = service->login_regexv.re_nsub + 1;
                            match_buf = malloc(sizeof(regmatch_t) * size);
                            if (regexec(&service->login_regexv, preview_data, size, match_buf, 0) == 0) {
                                user_values = split(elts[2], ",");
                                strncpy(buf, preview_data + match_buf[1].rm_so, match_buf[1].rm_eo - match_buf[1].rm_so);
                                buf[match_buf[1].rm_eo - match_buf[1].rm_so] = '\0';
                                loginid = malloc(strlen(buf));
                                if (urldecode(buf, loginid) < 0) {
                                    debugs(1, "ERROR url deocde failed: %s\n", buf);
                                } else {
                                    s1 = strchr(loginid, (int)'@');
                                    if (s1) {
                                        s1++;
                                        login_domain = malloc(strlen(s1) + 3);
                                        login_domain[0] = '|';
                                        strncpy(login_domain + 1, s1, strlen(s1));
                                        login_domain[strlen(s1) + 1] = '|';
                                        login_domain[strlen(s1) + 2] = '\0';
                                    }

                                    personal = 1;
                                    for (i = 0; user_values[i] != NULL; i++) {
                                        if (strcasecmp(user_values[i], loginid) == 0) {
                                            personal = 0;
                                            break;
                                        }
                                    }
                                }
                                strcpy(operation, "login");
                                free(user_values);
                            }
                            free(match_buf);
                        }

                        tokens = split(elts[1], ",");
                        for (i = 0; tokens[i] != NULL; i++) {
                            strcpy(buf, tokens[i]);
                            s1 = strtok(buf, "=");
                            if (!strcmp(service_id, s1) || (s1[strlen(s1) -1] == '/' && !strncmp(service_id, s1, strlen(s1)))) {
                                match = 1;
                                s1 = strtok(NULL, "=");
                                if (s1 == NULL) {
                                    debugs(1, "ERROR invalid token %s\n", tokens[i]);
                                    continue;
                                }
                                if (strstr(s1, "+enterprise+") != NULL && personal) {
                                    match = 0;
                                }
                                if (strstr(s1, "+personal+") != NULL && !personal) {
                                    match = 0;
                                }

                                if (strstr(s1, "+update+") != NULL && strstr(allowed, "update") == NULL) {
                                    strcat(allowed, "+update");
                                }
                                if (!strcmp(operation, "login") && (s2 = strstr(s1, "+login_domain")) != NULL) {
                                    if (login_domain) {
                                        if (strstr(s2, login_domain) == NULL) {
                                            match = 0;
                                        }
                                    } else {
                                        match = 0;
                                    }
                                }
                                if (strstr(s1, "+shared+") != NULL) {
                                    if (strstr(allowed, "share") == NULL) {
                                        strcat(allowed, "+share");
                                    }
                                    if ((s2 = strstr(s1, "+share_user")) != NULL) {
                                        s2 = strtok(s2, "+");
                                        if (share_user) {
                                            share_user = realloc(share_user, strlen(share_user) + strlen(s2) + 1);
                                        } else {
                                            share_user = malloc(strlen(s2) + 1);
                                        }
                                        strcpy(share_user, s2);
                                    }
                                }
                                if (strstr(s1, "+view+") != NULL && strstr(allowed, "view") == NULL) {
                                    strcat(allowed, "+view");
                                }

                                if (!strcmp(operation, "update") && strstr(s1, "+update+") == NULL) {
                                    match = 0;
                                } else if (!strcmp(operation, "download") && strstr(s1, "+download+") == NULL) {
                                    match = 0;
                                } else if (!strcmp(operation, "upload") && strstr(s1, "+upload+") == NULL) {
                                    match = 0;
                                } else if (!strcmp(operation, "view") && strstr(s1, "+view+") == NULL) {
                                    match = 0;
                                }
                                if (match && file_extension && (!strcmp(operation, "download") || !strcmp(operation, "upload")) && (s2 = strstr(s1, "+fileext")) != NULL) {
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
                        }
                        data->allowed = ci_buffer_alloc(strlen(allowed) + 1);
                        strcpy(data->allowed, allowed);
                        if (share_user) {
                            data->share_user = ci_buffer_alloc(strlen(share_user) + 1);
                            strcpy(data->share_user, share_user);
                            free(share_user);
                        }
                        free(tokens);
                        free(elts);
                        free(value);
                    }
                    if (file_extension != NULL) {
                        free(file_extension);
                    }

                    if (forbidden > 0) {
                        if (!strcmp(operation, "login")) {
                            debugs(0, "NOTICE %s; %s; %s; login; login with %s is denied\n", clientip, username, service_id, loginid);
                            free(loginid);
                            if (login_domain) {
                                free(login_domain);
                            }
                        } else {
                            debugs(0, "NOTICE %s; %s; %s; %s; %s is denied\n", clientip, username, service_id, operation, operation);
                        }
                        data->blocked = 1;
                        generate_response_page(req, data);
                        return CI_MOD_CONTINUE;
                    }
                }
                if (!strcmp(operation, "login")) {
                    debugs(0, "NOTICE %s; %s; %s; login; login with %s is allowed\n", clientip, username, service_id, loginid);
                    free(loginid);
                    if (login_domain) {
                        free(login_domain);
                    }
                }
            }

	    /* Get the content length header */
	    content_length = ci_http_content_length(req);
	    if ((content_length > 0) && (maxsize > 0) && (content_length >= maxsize)) {
		debugs(2, "DEBUG No antivir check, content-length upper than maxsize (%" PRINTF_OFF_T " > %d)\n", (CAST_OFF_T) content_length, (int) maxsize);
		return CI_MOD_ALLOW204;
	    }

            /* No data, so nothing to scan */
            if (!data || !ci_req_hasbody(req)) {
                debugs(2, "DEBUG No body data, allow 204\n");
                return CI_MOD_ALLOW204;
            }

            if (data->service == NULL) {
                return CI_MOD_ALLOW204;
            } else if (!strcmp(operation, "download") || !strcmp(operation, "upload")) {
                /* Get out if we have not detected something to scan */
                if (scanit == 0) {
                    debugs(0, "NOTICE %s; %s; %s; %s; %s is allowed\n", clientip, username, service_id, operation, operation);
                    return CI_MOD_ALLOW204;
                }
            } else if (strstr(operation, "share") == NULL && (no_acl || !strcmp(operation, "is_update"))) {
                debugs(0, "NOTICE %s; %s; %s; %s; %s is allowed\n", clientip,username, service_id, operation, operation);
                return CI_MOD_ALLOW204;
            }

	    data->url = ci_buffer_alloc(strlen(httpinf.url)+1);
	    strcpy(data->url, httpinf.url);

	    data->user = ci_buffer_alloc(strlen(username)+1);
	    strcpy(data->user, username);

            if (clientip) {
	        data->clientip = ci_buffer_alloc(strlen(clientip)+1);
	        strcpy(data->clientip, clientip);
            }

            data->operation = ci_buffer_alloc(strlen(operation)+1);
            strcpy(data->operation, operation); 
    } else {

	debugs(1, "WARNING bad http header, can not check URL, Content-Type and Content-Length.\n");
        return CI_MOD_ERROR;

    }

    if (preview_data_len == 0) {
	debugs(2, "DEBUG Can not begin to scan url: No preview data.\n");
    }

    data->body = ci_simple_file_new(0);
    if ((SEND_PERCENT_BYTES >= 0) && (START_SEND_AFTER == 0)) {
        ci_req_unlock_data(req);
        ci_simple_file_lock_all(data->body);
    }
    if (!data->body)
        return CI_ERROR;

    if (preview_data_len) {
        if (ci_simple_file_write(data->body, preview_data, preview_data_len, ci_req_hasalldata(req)) == CI_ERROR)
            return CI_ERROR;
    }

    debugs(2, "DEBUG End of method squidscas_check_preview_handler\n");

    return CI_MOD_CONTINUE;
}

int squidscas_read_from_net(char *buf, int len, int iseof, ci_request_t * req)
{
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
        debugs(1, "LOG No more antivir check, downloaded stream is upper than maxsize (%d>%d)\n", (int)data->body->bytes_in, (int)maxsize);
    } else if (SEND_PERCENT_BYTES && (START_SEND_AFTER < data->body->bytes_in)) {
        ci_req_unlock_data(req);
        allow_transfer = (SEND_PERCENT_BYTES * (data->body->endpos + len)) / 100;
        ci_simple_file_unlock(data->body, allow_transfer);
    }

    return ci_simple_file_write(data->body, buf, len, iseof);
}

int squidscas_write_to_net(char *buf, int len, ci_request_t * req)
{
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
        bytes =0;

    return bytes;
}

int squidscas_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                   ci_request_t * req)
{

    if (rbuf && rlen) {
        *rlen = squidscas_read_from_net(rbuf, *rlen, iseof, req);
        if (*rlen == CI_ERROR)
            return CI_ERROR;
        else if (*rlen < 0)
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

int squidscas_end_of_data_handler(ci_request_t * req)
{
    scas_req_data_t *data = ci_service_data(req);
    ci_simple_file_t *body;

    /* If local path was specified then generate unique file name to copy data.
    It can be used to put banned files and viri in quarantine directory. */
    char mime[LOW_BUFF];
    char checksum[LOW_BUFF];
    const scas_virus_t *virus;
    char fileref[SMALL_BUFF];
    char targetf[MAX_URL];
    int ret = 0;

    debugs(2, "DEBUG ending request data handler.\n");

    /* Nothing more to scan */
    if (!data || !data->body)
        return CI_MOD_DONE;

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
                for (i = 0; data->service->update_urls[i] != NULL; i++) {
                    if (strstr(data->url, data->service->update_urls[i]) != NULL) {
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
                    if (regexec(&data->service->share_regexv, s1, size, match_buf, 0)) {
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
        for (virus = (scas_virus_t *)ci_list_first(virus_list); virus != NULL ; virus = (scas_virus_t *)ci_list_next(virus_list)) {
            if (strcmp(checksum, virus->checksum) == 0) {
                data->virus = 1;
                debugs(1, "LOG Virus found in %s ending download to %s [%s]\n", data->url, data->user, virus->id);
                generate_response_page(req, data);
                return CI_MOD_DONE;
            }
        }
    }

    /* Copy file */
    srand(time(NULL));
    if (has_invalid_chars(INVALID_CHARS, get_filename_ext(data->url)) == 1) {
        snprintf(fileref, sizeof(fileref), "%s%s_%s_%d_%d", PREFIX_SCAN, data->user, data->clientip, (int)time(NULL), (int)rand() % 99);
    } else {
        snprintf(fileref, sizeof(fileref), "%s%s_%s_%d_%d.%s", PREFIX_SCAN, data->user, data->clientip, (int)time(NULL), (int)rand() % 99, get_filename_ext(data->url));
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

void set_istag(ci_service_xdata_t * srv_xdata)
{
    char istag[SERVICE_ISTAG_SIZE + 1];


    snprintf(istag, SERVICE_ISTAG_SIZE, "-%d-%s-%d%d",1, "squidscas", 1, 0);
    istag[SERVICE_ISTAG_SIZE] = '\0';
    ci_service_set_istag(srv_xdata, istag);
    debugs(2, "DEBUG setting istag to %s\n", istag);
}

/* util.c */

/* NUL-terminated version of strncpy() */
void xstrncpy (char *dest, const char *src, size_t n)
{
    if ( (src == NULL) || (strcmp(src, "") == 0))
        return;
    strncpy(dest, src, n-1);
    dest[n-1] = 0;
}

/* Emulate the Perl chomp() method: remove \r and \n from end of string */
void chomp (char *str)
{
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

/* return 0 if path exists, -1 otherwise */
int isPathExists(const char *path)
{
    struct stat sb;

    if ( (path == NULL) || (strcmp(path, "") == 0) ) return -1;

    if (lstat(path, &sb) != 0) {
        return -1;
    }

    return 0;
}


/* return 0 if path is secure, -1 otherwise */
int isPathSecure(const char *path)
{
    struct stat sb;

    /* no path => unreal, that's possible ! */
    if (path == NULL) return -1;

    /* file doesn't exist or access denied = secure */
    /* fopen will fail */
    if (lstat(path, &sb) != 0) return 0;

    /* File is not a regular file => unsecure */
    if ( S_ISLNK(sb.st_mode ) ) return -1;
    if ( S_ISDIR(sb.st_mode ) ) return -1;
    if ( S_ISCHR(sb.st_mode ) ) return -1;
    if ( S_ISBLK(sb.st_mode ) ) return -1;
    if ( S_ISFIFO(sb.st_mode ) ) return -1;
    if ( S_ISSOCK(sb.st_mode ) ) return -1;

    return 0;
}

/* return 0 if file exists and is readable, -1 otherwise */
int
isFileExists(const char *path)
{
    struct stat sb;

    /* no path => unreal, that's possible ! */
    if (path == NULL) return -1;

    /* file doesn't exist or access denied */
    if (lstat(path, &sb) != 0) return -1;

    /* File is not a regular file */
    if ( S_ISDIR(sb.st_mode ) ) return -1;
    if ( S_ISCHR(sb.st_mode ) ) return -1;
    if ( S_ISBLK(sb.st_mode ) ) return -1;
    if ( S_ISFIFO(sb.st_mode ) ) return -1;
    if ( S_ISSOCK(sb.st_mode ) ) return -1;

    return 0;
}


/* Remove spaces and tabs from beginning and end of a string */
void trim(char *str)
{
    int i = 0;
    int j = 0;

    /* Remove spaces and tabs from beginning */
    while ( (str[i] == ' ') || (str[i] == '\t') ) {
        i++;
    }
    if (i > 0) {
        for (j = i; j < strlen(str); j++) {
            str[j-i] = str[j];
        }
        str[j-i] = '\0';
    }

    /* Now remove spaces and tabs from end */
    i = strlen(str) - 1;
    while ( (str[i] == ' ') || (str[i] == '\t')) {
        i--;
    }
    if ( i < (strlen(str) - 1) ) {
        str[i+1] = '\0';
    }
}

/* Try to emulate the Perl split() method: str is splitted on the
   all occurence of delim. Take care that empty fields are not returned */
char** split( char* str, const char* delim)
{
    int size = 0;
    char** splitted = NULL;
    char *tmp = NULL;
    tmp = strtok(str, delim);
    while (tmp != NULL) {
        splitted = (char**) realloc(splitted, sizeof(char**) * (size+1));
        if (splitted != NULL) {
            splitted[size] = tmp;
        } else {
            return(NULL);
        }
        tmp = strtok(NULL, delim);
        size++;
    }
    free(tmp);
    tmp = NULL;
    /* add null at end of array to help ptrarray_length */
    splitted = (char**) realloc(splitted, sizeof(char**) * (size+1));
    if (splitted != NULL) {
        splitted[size] = NULL;
    } else {
        return(NULL);
    }

    return splitted;
}

/* Return the length of a pointer array. Must be ended by NULL */
int ptrarray_length(char** arr)
{
    int i = 0;
    while(arr[i] != NULL) i++;
    return i;
}

void * xmallox (size_t len)
{
    void *memres = malloc (len);
    if (memres == NULL) {
        fprintf(stderr, "Running Out of Memory!!!\n");
        exit(EXIT_FAILURE);
    }
    return memres;
}

size_t xstrnlen(const char *s, size_t n)
{
    const char *p = (const char *)memchr(s, 0, n);
    return(p ? p-s : n);
}


/* pattern.c */

int isIpAddress(char *src_addr)
{
    char *ptr;
    int address;
    int i;
    char *s = (char *) malloc (sizeof (char) * LOW_CHAR);

    xstrncpy(s, src_addr, LOW_CHAR);

    /* make sure we have numbers and dots only! */
    if(strspn(s, "0123456789.") != strlen(s)) {
        free(s);
        return 1;
    }

    /* split up each number from string */
    ptr = strtok(s, ".");
    if(ptr == NULL) {
        free(s);
        return 1;
    }
    address = atoi(ptr);
    if(address < 0 || address > 255) {
        free(s);
        free(ptr);
        return 1;
    }

    for(i = 2; i < 4; i++) {
        ptr = strtok(NULL, ".");
        if (ptr == NULL) {
            free(s);
            return 1;
        }
        address = atoi(ptr);
        if (address < 0 || address > 255) {
            free(ptr);
            free(s);
            return 1;
        }
    }
    free(s);

    return 0;
}


int simple_pattern_compare(const char *str, const int type)
{
    int i = 0;

    /* pass througth all regex pattern */
    for (i = 0; i < pattc; i++) {
        if ( (patterns[i].type == type) && (regexec(&patterns[i].regexv, str, 0, 0, 0) == 0) ) {
            switch(type) {
                /* return 1 if string matches whitelist pattern */
                case WHITELIST:
                    debugs(2, "DEBUG whitelist (%s) matched: %s\n", patterns[i].pattern, str);
                    return 1;
                case BLACKLIST:
                    debugs(2, "DEBUG blacklist (%s) matched: %s\n", patterns[i].pattern, str);
                    return 1;
                    /* return 1 if string matches abort pattern */
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

int client_pattern_compare(const char *ip, char *name)
{
    int i = 0;

    /* pass througth all regex pattern */
    for (i = 0; i < pattc; i++) {
        if ( (scan_mode == SCAN_ALL) && (patterns[i].type == TRUSTCLIENT) ) {
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
        } else if ( (scan_mode == SCAN_NONE) && (patterns[i].type == UNTRUSTCLIENT) ) {
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
int load_patterns()
{
    char *buf = NULL;
    FILE *fp  = NULL;
    int ret   = 0;

    if (isPathExists(CONFIGDIR "/" CONFIG_FILE) == 0) {
        fp = fopen(CONFIGDIR "/" CONFIG_FILE, "rt");
        debugs(0, "LOG Reading configuration from %s\n", CONFIGDIR "/" CONFIG_FILE);
    }


    if (fp == NULL) {
        debugs(0, "FATAL unable to open configuration file: %s\n", CONFIGDIR "/" CONFIG_FILE);
        return 0;
    }

    buf = (char *)malloc(sizeof(char)*LOW_BUFF*2);
    if (buf == NULL) {
        debugs(0, "FATAL unable to allocate memory in load_patterns()\n");
        fclose(fp);
        return 0;
    }
    while ((fgets(buf, LOW_BUFF, fp) != NULL)) {
        /* chop newline */
        chomp(buf);
        /* add to regex patterns array */
        if ( (strlen(buf) > 0) && (add_pattern(buf, 0) == 0) ) {
	    debugs(0, "FATAL can't add pattern: %s\n", buf);
            free(buf);
            fclose(fp);
            return 0;
        }
    }
    free(buf);
    ret = fclose(fp);
    if (ret != 0) {
        debugs(0, "ERROR Can't close configuration file (%d)\n", ret);
    }

    /* Set default values */
    if (clamd_local == NULL) {
        if (clamd_ip == NULL) {
            clamd_ip = (char *) malloc (sizeof (char) * SMALL_CHAR);
            if(clamd_ip == NULL) {
                debugs(0, "FATAL unable to allocate memory in load_patterns()\n");
                return 0;
            }
            xstrncpy(clamd_ip, CLAMD_SERVER, SMALL_CHAR);
        }

        if (clamd_port == NULL) {
            clamd_port = (char *) malloc (sizeof (char) * LOW_CHAR);
            if(clamd_port == NULL) {
                debugs(0, "FATAL unable to allocate memory in load_patterns()\n");
                return 0;
            }
            xstrncpy(clamd_port, CLAMD_PORT, LOW_CHAR);
        }
    }

    if (redirect_url == NULL) {
	debugs(0, "FATAL you must set redirect_url or use c-icap 0.2.x or upper to use templates\n");
	return 0;
    }

    return 1;
}

int growPatternArray(SCPattern item)
{
    void *_tmp = NULL;
    if (pattc == current_pattern_size) {
        if (current_pattern_size == 0)
            current_pattern_size = PATTERN_ARR_SIZE;
        else
            current_pattern_size += PATTERN_ARR_SIZE;

        _tmp = realloc(patterns, (current_pattern_size * sizeof(SCPattern)));
        if (!_tmp) {
            return(-1);
        }

        patterns = (SCPattern*)_tmp;
    }
    patterns[pattc] = item;
    pattc++;

    return(pattc);
}

/* Add regexp expression to patterns array */
int add_pattern(char *s, int level)
{
    char *first = NULL;
    char *type  = NULL;
    int stored = 0;
    int regex_flags = REG_NOSUB;
    SCPattern currItem;
    char *end = NULL;

    /* skip empty and commented lines */
    if ( (xstrnlen(s, LOW_BUFF) == 0) || (strncmp(s, "#", 1) == 0)) return 1;

    /* Config file directives are construct as follow: name value */
    type = (char *)malloc(sizeof(char)*LOW_CHAR);
    first = (char *)malloc(sizeof(char)*LOW_BUFF);
    stored = sscanf(s, "%31s %255[^#]", type, first);

    if (stored < 2) {
        debugs(0, "FATAL Bad configuration line for [%s]\n", s);
        free(type);
        free(first);
        return 0;
    }
    /* remove extra space or tabulation */
    trim(first);

    debugs(0, "LOG Reading directive %s with value %s\n", type, first);
    /* URl to redirect Squid on virus found */
    if(strcmp(type, "redirect") == 0) {
        redirect_url = (char *) malloc (sizeof (char) * LOW_BUFF);
        if(redirect_url == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        } else {
            xstrncpy(redirect_url, first, LOW_BUFF);
        }
        free(type);
        free(first);
        return 1;
    }

    /* Path for file scan */
    if(strcmp(type, "scanpath") == 0) {
        scan_path = (char *) malloc (sizeof (char) * LOW_BUFF);
        if(scan_path == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        } else {
            if (isPathExists(first) == 0) {
                xstrncpy(scan_path, first, LOW_BUFF);
            } else {
                debugs(0, "LOG Wrong path to scanpath, disabling.\n");
		free(scan_path);
            }
        }
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "dnslookup") == 0) {
        if (dnslookup == 1)
            dnslookup = atoi(first);
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "timeout") == 0) {
        timeout = atoi(first);
        if (timeout > 10)
            timeout = 10;
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "stat") == 0) {
        statit = atoi(first);
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "clamd_ip") == 0) {
        clamd_ip = (char *) malloc (sizeof (char) * SMALL_CHAR);
        if (clamd_ip == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        } else {
            xstrncpy(clamd_ip, first, SMALL_CHAR);
        }
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "clamd_port") == 0) {
        clamd_port = (char *) malloc (sizeof (char) * LOW_CHAR);
        if(clamd_port == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        } else {
            xstrncpy(clamd_port, first, LOW_CHAR);
        }
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "clamd_local") == 0) {
        clamd_local = (char *) malloc (sizeof (char) * LOW_BUFF);
        if(clamd_local == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        } else {
            xstrncpy(clamd_local, first, LOW_BUFF);
        }
        free(type);
        free(first);
        return 1;
    }

    if (strcmp(type, "maxsize") == 0) {
        maxsize = ci_strto_off_t(first, &end, 10);
        if ((maxsize == 0 && errno != 0) || maxsize < 0)
            maxsize = 0;
        if (*end == 'k' || *end == 'K')
            maxsize = maxsize * 1024;
        else if (*end == 'm' || *end == 'M')
            maxsize = maxsize * 1024 * 1024;
        else if (*end == 'g' || *end == 'G')
            maxsize = maxsize * 1024 * 1024 * 1024;
        free(type);
        free(first);
        return 1;
    }

    /* Scan mode */
    if(strcmp(type, "scan_mode") == 0) {
	char *scan_type = (char *) malloc (sizeof (char) * LOW_BUFF);
        if(scan_type == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(scan_type);
            free(type);
            free(first);
            return 0;
        } else {
            if (strncmp(first, "ScanNothingExcept", sizeof (char) * LOW_BUFF) == 0) {
                scan_mode = SCAN_NONE;
                debugs(0, "LOG setting squidscas scan mode to 'ScanNothingExcept'.\n");
	    } else if (strncmp(first, "ScanAllExcept", sizeof (char) * LOW_BUFF) == 0) {
                scan_mode = SCAN_ALL;
                debugs(0, "LOG setting squidscas scan mode to 'ScanAllExcept'.\n");
            } else if (strlen(first) > 0) {
                fprintf(stderr, "incorrect value in scan_mode, failling back to ScanAllExcept mode.\n");
                scan_mode = SCAN_ALL;
            }
        }
        free(scan_type);
        free(type);
        free(first);
        return 1;
    }

    /* SECIOSS */
    if(strcmp(type, "memcached_servers") == 0) {
        char **argv = split(first, " ");
        mc_cfg_servers_set((const char **)argv);
        free(argv);
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "servicelist") == 0) {
        scas_cfg_services_set(first);
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "viruslist") == 0) {
        scas_cfg_virus_list_set(first);
        free(type);
        free(first);
        return 1;
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
    } else if(strcmp(type, "whitelist") == 0) {
        currItem.type = WHITELIST;
	if (level == 0) {
		if (readFileContent(first, type) == 1) {
			free(type);
			free(first);
			return 1;
		}
	}
    } else if(strcmp(type, "blacklist") == 0) {
        currItem.type = BLACKLIST;
	if (level == 0) {
		if (readFileContent(first, type) == 1) {
			free(type);
			free(first);
			return 1;
		}
	}
    } else if(strcmp(type, "trustuser") == 0) {
        currItem.type = TRUSTUSER;
    } else if(strcmp(type, "trustclient") == 0) {
        currItem.type = TRUSTCLIENT;
    } else if(strcmp(type, "untrustuser") == 0) {
        currItem.type = UNTRUSTUSER;
    } else if(strcmp(type, "untrustclient") == 0) {
        currItem.type = UNTRUSTCLIENT;
    } else if ( (strcmp(type, "squid_ip") != 0) && (strcmp(type, "squid_port") != 0) && (strcmp(type, "maxredir") != 0) && (strcmp(type, "useragent") != 0) && (strcmp(type, "trust_cache") != 0) ) {
        fprintf(stderr, "WARNING Bad configuration keyword: %s\n", s);
        free(type);
        free(first);
        return 1;
    }

    /* Fill the pattern flag */
    currItem.flag = regex_flags;

    /* Fill pattern array */
    currItem.pattern = malloc(sizeof(char)*(strlen(first)+1));
    if (currItem.pattern == NULL) {
        fprintf(stderr, "unable to allocate new pattern in add_to_patterns()\n");
        free(type);
        free(first);
        return 0;
    }
    strncpy(currItem.pattern, first, strlen(first) + 1);
    if ((stored = regcomp(&currItem.regexv, currItem.pattern, currItem.flag)) != 0) {
        debugs(0, "ERROR Invalid regex pattern: %s\n", currItem.pattern);
    } else {
        if (growPatternArray(currItem) < 0) {
            fprintf(stderr, "unable to allocate new pattern in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        }
    }
    free(type);
    free(first);
    return 1;
}

/* return 1 when the file have some regex content, 0 otherwise */
int
readFileContent(char *filepath, char *kind)
{
    char *buf = NULL;
    FILE *fp  = NULL;
    int ret   = 0;
    char str[LOW_BUFF+LOW_CHAR+1];

    if (isFileExists(filepath) != 0) {
	return 0;
    }

    debugs(0, "LOG Reading %s information from file from %s\n", kind, filepath);
    fp = fopen(filepath, "rt");
    if (fp == NULL) {
        debugs(0, "FATAL unable to open %s file: %s\n", kind, filepath);
        return 0;
    }

    buf = (char *)malloc(sizeof(char)*LOW_BUFF*2);
    if (buf == NULL) {
        debugs(0, "FATAL unable to allocate memory in readFileContent()\n");
        fclose(fp);
        return 0;
    }
    while ((fgets(buf, LOW_BUFF, fp) != NULL)) {
        /* chop newline */
        chomp(buf);
        /* add to regex patterns array */
        snprintf(str, LOW_CHAR + LOW_BUFF, "%s %s", kind, buf);
        if ( (strlen(buf) > 0) && (add_pattern(str, 1) == 0) ) {
            free(buf);
            fclose(fp);
            return 0;
        }
    }
    free(buf);
    ret = fclose(fp);
    if (ret != 0) {
        debugs(0, "ERROR Can't close file %s (%d)\n", filepath, ret);
    }

    return 1;
}

int extract_http_info(ci_request_t * req, ci_headers_list_t * req_header,
                      struct http_info *httpinf)
{
    char *str;
    int i = 0;

    /* Format of the HTTP header we want to parse:
       GET http://www.squid-cache.org/Doc/config/icap_service HTTP/1.1
       */
    httpinf->url[0]='\0';
    httpinf->method[0] = '\0';

    str = req_header->headers[0];

    /* if we can't find a space character, there's somethings wrong */
    if (strchr(str, ' ') == NULL) {
        return 0;
    }

    /* extract the HTTP method */
    while (*str != ' ' && i < (MAX_METHOD_SIZE - 1)) {
        httpinf->method[i] = *str;
        str++;
        i++;
    }
    httpinf->method[i] = '\0';
    debugs(3, "DEBUG method %s\n", httpinf->method);

    /* Extract the URL part of the header */
    while (*str == ' ') str++;
    i = 0;
    while (*str != ' ' && i < (MAX_URL - 1)) {
        httpinf->url[i] = *str;
        i++;
        str++;
    }
    httpinf->url[i] = '\0';
    debugs(3, "DEBUG url %s\n", httpinf->url);
    if (*str != ' ') {
        return 0;
    }
    /* we must find the HTTP version after all */
    while (*str == ' ')
        str++;
    if (*str != 'H' || *(str + 4) != '/') {
        return 0;
    }

    return 1;
}

const char *http_content_type(ci_request_t * req)
{
    ci_headers_list_t *heads;
    const char *val;
    if (!(heads =  ci_http_response_headers(req))) {
        /* Then maybe is a reqmod request, try to get request headers */
        if (!(heads = ci_http_request_headers(req)))
            return NULL;
    }
    if (!(val = ci_headers_value(heads, "Content-Type")))
        return NULL;

    return val;
}

void free_global()
{
    free(clamd_local);
    free(clamd_ip);
    free(clamd_port);
    free(clamd_curr_ip);
    free(redirect_url);
    free(scan_path);
    if (patterns != NULL) {
        while (pattc > 0) {
            pattc--;
            regfree(&patterns[pattc].regexv);
            free(patterns[pattc].pattern);
        }
        free(patterns);
        patterns = NULL;
    }
    memcached_free(MC);
    ci_list_destroy(servers_list);
    servers_list = NULL;
    if (services_list) {
        ci_list_destroy(services_list);
        services_list = NULL;
    }
    if (virus_list) {
        ci_list_destroy(virus_list);
        virus_list = NULL;
    }
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

void generate_response_page(ci_request_t *req, scas_req_data_t *data)
{
    if (redirect_url != NULL) {
        char *urlredir = (char *) malloc( sizeof(char)*MAX_URL );
        snprintf(urlredir, MAX_URL, "%s?msg=%s"
                 , redirect_url
                 , data->virus ? "auth_err_101" : "auth_err_003"
		 );
        generate_redirect_page(urlredir, req, data);
        free(urlredir);
    }
}

void generate_redirect_page(char * redirect, ci_request_t * req, scas_req_data_t * data)
{
    int new_size = 0;
    char buf[MAX_URL];
    ci_membuf_t *error_page;

    new_size = strlen(blocked_header_message) + strlen(redirect) + strlen(blocked_footer_message) + 10;

    if ( ci_http_response_headers(req))
        ci_http_response_reset_headers(req);
    else
        ci_http_response_create(req, 1, 1);

    debugs(2, "DEBUG creating redirection page\n");

    snprintf(buf, MAX_URL, "Location: %s", redirect);
    /*strcat(buf, ";");*/

    debugs(3, "DEBUG %s\n", buf);

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
        ((scas_req_data_t *) data)->error_page = error_page;
        ci_membuf_write(error_page, (char *) blocked_header_message, strlen(blocked_header_message), 0);
        ci_membuf_write(error_page, (char *) redirect, strlen(redirect), 0);
        ci_membuf_write(error_page, (char *) blocked_footer_message, strlen(blocked_footer_message), 1);
    }
    debugs(3, "DEBUG done\n");

}


/**
 * Searches all occurrences of old into s
 * and replaces with new
 */
char * replace(const char *s, const char *old, const char *new)
{
    char *ret;
    int i, count = 0;
    size_t newlen = strlen(new);
    size_t oldlen = strlen(old);

    for (i = 0; s[i] != '\0'; i++) {
        if (strstr(&s[i], old) == &s[i]) {
            count++;
            i += oldlen - 1;
        }
    }
    ret = malloc(i + 1 + count * (newlen - oldlen));
    if (ret != NULL) {
        i = 0;
        while (*s) {
            if (strstr(s, old) == s) {
                strcpy(&ret[i], new);
                i += newlen;
                s += oldlen;
            } else {
                ret[i++] = *s++;
            }
        }
        ret[i] = '\0';
    }

    return ret;
}

/**
 * returns file name extension
 */
const char *get_filename_ext(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename)
        return "";
    return dot + 1;
}

/**
 * simple file copy
 */
int copy_file(int fd_src, const char  *fname_dst)
{
    char buf[HIGH_BUFF];
    ssize_t nread, total_read;
    int fd_dst;

    fd_dst = open(fname_dst, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if(fd_dst < 0) {
        debugs(0, "DEBUG could not create [%s]\n", fname_dst);
        return  -1;
    }

    total_read = 0;
    while (nread = read(fd_src, buf, sizeof(buf)), nread > 0) {
        total_read += nread;
        debugs(3, "DEBUG read [%d] bytes of data\n", (int) nread);
        char *out_ptr = buf;
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
    return  0;
}

/**
 * check for invalid chars in string
 */
int has_invalid_chars(const char *inv_chars, const char *target)
{
    const char *c = target;
    debugs(3, "DEBUG checking for troublesome chars [%s] in [%s]\n", inv_chars, target);
    while (*c) {
        if (strchr(inv_chars, *c)) {
            debugs(3, "WARNING found troublesome char [%c] in [%s]\n", *c, target);
            return 1;
        }
        c++;
    }
    debugs(3, "DEBUG no troublesome chars in [%s]\n", target);
    return 0;
}

/* SECIOSS */

ci_headers_list_t* get_headers_from_entities(ci_encaps_entity_t** entities, int type)
{
    ci_encaps_entity_t* e;
    while ((e = *entities++) != NULL) {
        if (e->type == type)
            return (ci_headers_list_t*)(e->entity);
    }
    return NULL;
}

int mimetype(int fd_src, char *mime)
{
    magic_t magic;
    char buf[MAGIC_HEADER_SIZE];
    ssize_t nread;
    const char *str = NULL;

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

char *tolowerstring(char *str)
{
    int i = 0;
    while (str[i] != '\0') {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] = tolower((unsigned char)str[i]);
        }
        i++;
    }
    return str;
}

int sha1sum(int fd_src, char *checksum)
{
    char buf[HIGH_BUFF];
    SHA_CTX sha1;
    unsigned char digest[20];

    SHA1_Init(&sha1);
    while (read(fd_src, buf, sizeof(buf)) > 0) {
        SHA1_Update(&sha1, (const unsigned char *)buf, sizeof(buf));
    }
    SHA1_Final(digest, &sha1);

    sprintf(checksum, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                       digest[0], digest[1], digest[2], digest[3],
                       digest[4], digest[5], digest[6], digest[7],
                       digest[8], digest[9], digest[10], digest[11],
                       digest[12], digest[13], digest[14], digest[15],
                       digest[16], digest[17], digest[18], digest[19]);

    tolowerstring(checksum);

    return 0;
}

inline int ishex(int x)
{
    return (x >= '0' && x <= '9') ||
           (x >= 'a' && x <= 'f') ||
           (x >= 'A' && x <= 'F');
}
 
int urldecode(const char *s, char *dec)
{
    char *o;
    const char *end = s + strlen(s);
    int c;

    for (o = dec; s <= end; o++) {
        c = *s++;
        if (c == '+') c = ' ';
        else if (c == '%' && (!ishex(*s++) ||
                            !ishex(*s++) ||
                            !sscanf(s - 2, "%2x", &c)))
            return -1;
 
        if (dec) *o = c;
    }

    return o - dec;
}

int mc_cfg_servers_set(const char **argv)
{
    int argc;
    char *s;
    mc_server_t srv;

    if (!servers_list) {
        servers_list = ci_list_create(4096, sizeof(mc_server_t));
        if (!servers_list) {
            debugs(1, "Error allocating memory for mc_servers list!\n");
            return 0;
        }
    }

    for (argc = 0; argv[argc] != NULL; argc++) {

        strncpy(srv.hostname, argv[argc], HOSTNAME_LEN);
        srv.hostname[HOSTNAME_LEN - 1] = '\0';
        if (srv.hostname[0] != '/' && (s = strchr(srv.hostname, ':')) != NULL) {
            *s = '\0';
            s++;
            srv.port = atoi(s);
            if (!srv.port)
                srv.port = 11211;
        } else
            srv.port = 11211;
        debugs(0, "LOG Setup memcached server %s:%d\n", srv.hostname, srv.port);
    }
    ci_list_push_back(servers_list, &srv);

    return argc;
}

int scas_cfg_services_set(const char *filepath)
{
    char *buf = NULL;
    FILE *fp  = NULL;
    int ret   = 0;
    char str[1024];
    char **elts;
    char *s = NULL;
    char *urls = NULL;
    char *login = NULL;
    char *updates = NULL;
    char *share = NULL;
    scas_service_t service;
    int i;

    if (isFileExists(filepath) != 0) {
        return 0;
    }

    if (!services_list) {
        services_list = ci_list_create(4096, sizeof(scas_service_t));
        if (!servers_list) {
            debugs(1, "Error allocating memory for scas_services list!\n");
            return 0;
        }
    }

    debugs(0, "LOG Reading information from file from %s\n", filepath);
    fp = fopen(filepath, "rt");
    if (fp == NULL) {
        debugs(0, "FATAL unable to open file: %s\n", filepath);
        return 0;
    }

    buf = (char *)malloc(sizeof(char)*SMALL_BUFF*2);
    if (buf == NULL) {
        debugs(0, "FATAL unable to allocate memory in scas_cfg_services_set()\n");
        fclose(fp);
        return 0;
    }
    while ((fgets(buf, SMALL_BUFF, fp) != NULL)) {
        /* chop newline */
        chomp(buf);
        if (strlen(buf) > 0) {
            login = NULL;
            updates = NULL;
            share = NULL;

            strcpy(str, buf);
            s = strtok(str, "\t");
            strncpy(service.id, str, ID_LEN);
            s = strtok(NULL, "\t");
            urls = malloc(strlen(s) + 1);
            strcpy(urls, s);
            s = strtok(NULL, "\t");
            if (s != NULL && strlen(s) > 0) {
                login = malloc(strlen(s) + 1);
                strcpy(login, s);
            }
            s = strtok(NULL, "\t");
            if (s != NULL && strlen(s) > 0) {
                updates = malloc(strlen(s) + 1);
                strcpy(updates, s);
            }
            s = strtok(NULL, "\t");
            if (s!= NULL && strlen(s) > 0) {
                share = malloc(strlen(s) + 1);
                strcpy(share, s);
            }

            service.urls = split(urls, ";");
            if (login && strcmp(login, " ")) {
                s = strtok(login, "#");
                service.login_url = malloc(strlen(s) + 1);
                strcpy(service.login_url, s);
                s = strtok(NULL, "#");
                if (s == NULL) {
                    debugs(0, "FATAL invalid login format: %s\n", service.id);
                    return 0;
                }
                if (regcomp(&service.login_regexv, s, REG_EXTENDED)) {
                    debugs(0, "FATAL login regex comple failed: %s\n", s);
                    return 0;
                }
            } else {
                service.login_url = NULL;
            }

            if (updates && strcmp(updates, " ")) {
                elts = split(updates, ";");
                for (i = 0; i < 10; i++) {
                    if (elts[i] == NULL) {
                        service.update_urls[i] = NULL;
                        service.update_params[i] = NULL;
                        break;
                    } else {
                        s = strtok(elts[i], "#");
                        service.update_urls[i] = s;
                        s = strtok(NULL, "#");
                        service.update_params[i] = s;
                    }
                }
                free(elts);
            } else {
                service.update_urls[0] = NULL;
                service.update_params[0] = NULL;
            }

            if (share && strcmp(share, " ")) {
                s = strtok(share, "#");
                if (regcomp(&service.share_url, s, REG_EXTENDED | REG_NOSUB)) {
                    debugs(0, "FATAL share url comple failed: %s\n", s);
                    return 0;
                }
                s = strtok(NULL, "#");
                if (s == NULL) {
                    debugs(0, "FATAL invalid share format: %s\n", service.id);
                    return 0;
                }
                if (regcomp(&service.share_regexv, s, REG_EXTENDED)) {
                    debugs(0, "FATAL share regex comple failed: %s\n", s);
                    return 0;
                }
                service.share = 1;
            } else {
                service.share = 0;
            }

            ci_list_push_back(services_list, &service);
        }
    }
    free(buf);
    ret = fclose(fp);
    if (ret != 0) {
        debugs(0, "ERROR Can't close file %s (%d)\n", filepath, ret);
    }

    return 1;
}

int scas_cfg_virus_list_set(const char *filepath)
{
    char *buf = NULL;
    FILE *fp  = NULL;
    int ret   = 0;
    char str[1024];
    char *s = NULL;
    scas_virus_t virus;

    if (isFileExists(filepath) != 0) {
        return 0;
    }

    if (!virus_list) {
        virus_list = ci_list_create(4096, sizeof(char *));
        if (!virus_list) {
            debugs(1, "Error allocating memory for virus list!\n");
            return 0;
        }
    }

    debugs(0, "LOG Reading information from file from %s\n", filepath);
    fp = fopen(filepath, "rt");
    if (fp == NULL) {
        debugs(0, "FATAL unable to open file: %s\n", filepath);
        return 0;
    }

    buf = (char *)malloc(sizeof(char)*LOW_BUFF*2);
    if (buf == NULL) {
        debugs(0, "FATAL unable to allocate memory in scas_cfg_virus_list_set()\n");
        fclose(fp);
        return 0;
    }
    while ((fgets(buf, LOW_BUFF, fp) != NULL)) {
        /* chop newline */
        chomp(buf);
        if (strlen(buf) > 0) {
            strcpy(str, buf);
            s = strtok(str, ",");
            strncpy(virus.id, str, ID_LEN);
            s = strtok(NULL, ",");
            if (s) {
                strncpy(virus.checksum, s, LOW_BUFF);
                ci_list_push_back(virus_list, &virus);
            }
        }
    }
    free(buf);
    ret = fclose(fp);
    if (ret != 0) {
        debugs(0, "ERROR Can't close file %s (%d)\n", filepath, ret);
    }

    return 1;
}
