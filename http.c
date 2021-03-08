#include "tls.h"
#include "http.h"
#include "ulog.h"
#include "token.h"
#include <string.h>
#include <stdio.h>

#define DEFAULT_AUTH_MODULE "pam"

/* size of the line buffer for each worker (request and header only)
 * requests that have longer headers will be rejected with 413
 * Note that cookies can be quite big and some browsers send them
 * in one line, so this should not be too small */
#define LINE_BUF_SIZE 32768

/* debug output - change the DBG(X) X to enable debugging output */
#ifdef RSERV_DEBUG
#define DBG(X) X
#else
#define DBG(X)
#endif

#include "rserr.h"

/* --- httpd --- */

#define PART_REQUEST 0
#define PART_HEADER  1
#define PART_BODY    2

#define METHOD_POST  1
#define METHOD_GET   2
#define METHOD_HEAD  3
#define METHOD_OTHER 8 /* for custom requests only */

/* attributes of a connection/worker */
#define CONNECTION_CLOSE  0x0001 /* Connection: close response behavior is requested */
#define HOST_HEADER       0x0002 /* headers contained Host: header (required for HTTP/1.1) */
#define HTTP_1_0          0x0004 /* the client requested HTTP/1.0 */
#define CONTENT_LENGTH    0x0008 /* Content-Length: was specified in the headers */
#define THREAD_OWNED      0x0010 /* the worker is owned by a thread and cannot removed */
#define THREAD_DISPOSE    0x0020 /* the thread should dispose of the worker */
#define CONTENT_TYPE      0x0040 /* message has a specific content type set */
#define CONTENT_FORM_UENC 0x0080 /* message content type is application/x-www-form-urlencoded */
#define WS_UPGRADE        0x0100 /* upgrade to WebSockets protocol */

struct buffer {
    struct buffer *next, *prev;
    int size, length;
    char data[1];
};

#ifndef WIN32
#include <sys/un.h> /* needed for unix sockets */
#endif
#include <time.h>

struct args {
	server_t *srv; /* server that instantiated this connection */
    SOCKET s;
	SOCKET ss;
	int msg_id;
	void *res1, *res2;
	/* the following entries are not populated by Rserve but can be used by server implemetations */
	char *buf, *sbuf;
	int   ver, bp, bl, sp, sl, flags;
	long  l1, l2;
	/* The following fields are informational, populated by Rserve */
    SAIN sa;
    int ucix;
#ifdef unix
    struct sockaddr_un su;
#endif
    char *line_buf;                /* line buffer (used for request and headers) */
    char *url, *body;              /* URL and request body */
    char *content_type;            /* content type (if set) */
    unsigned int line_pos, body_pos; /* positions in the buffers */
    long content_length;           /* desired content length */
    char part, method;             /* request part, method */
	int  attr;                     /* connection attributes */
    struct buffer *headers;        /* buffer holding header lines */
};

#define IS_HTTP_1_1(C) (((C)->attr & HTTP_1_0) == 0)

/* returns the HTTP/x.x string for a given connection - we support 1.0 and 1.1 only */
#define HTTP_SIG(C) (IS_HTTP_1_1(C) ? "HTTP/1.1" : "HTTP/1.0")

typedef struct {
	size_t size;
	char buf[1];
} buf_t;

/* free buffers starting from the tail(!!) */
static void free_buffer(struct buffer *buf) {
    if (!buf) return;
    if (buf->prev) free_buffer(buf->prev);
    free(buf);
}

#ifdef USE_HEADERS
/* allocate a new buffer */
static struct buffer *alloc_buffer(int size, struct buffer *parent) {
    struct buffer *buf = (struct buffer*) malloc(sizeof(struct buffer) + size);
    if (!buf) return buf;
    buf->next = 0;
    buf->prev = parent;
    if (parent) parent->next = buf;
    buf->size = size;
    buf->length = 0;
    return buf;
}

static buf_t *alloc_buf(size_t size) {
	buf_t *buf = (buf_t*) malloc(size + sizeof(buf_t));
	buf->size = size;
	return buf;
}

/* convert doubly-linked buffers into one big raw vector */
static buf_t *collect_buffers(struct buffer *buf) {
    buf_t *res;
    char *dst;
    size_t len = 0;
    if (!buf) return alloc_buf(0);
    while (buf->prev) { /* count the total length and find the root */
		len += buf->length;
		buf = buf->prev;
    }
	len += buf->length;
    res = alloc_buf(len + 1);
    dst = res->buf;
    while (buf) {
		memcpy(dst, buf->data, buf->length);
		dst += buf->length;
		buf = buf->next;
    }
	res->buf[len] = 0; /* guarantee a trailing NUL so it can be used as a string */
    return res;
}
#endif

static void free_args(args_t *c)
{
    DBG(printf("finalizing worker %p\n", (void*) c));
    if (c->url) {
		free(c->url);
		c->url = NULL;
    }
	if (c->line_buf) {
		free(c->line_buf);
		c->line_buf = NULL;
	}
    if (c->body) {
		free(c->body);
		c->body = NULL;
    }
	
    if (c->content_type) {
		free(c->content_type);
		c->content_type = NULL;
    }
    if (c->headers) {
		free_buffer(c->headers);
		c->headers = NULL;
    }
    if (c->s != INVALID_SOCKET) {
		closesocket(c->s);
		c->s = INVALID_SOCKET;
    }
}

static int send_response(args_t *c, const char *buf, unsigned int len)
{
	server_t *srv = c->srv;
    unsigned int i = 0;
    /* we have to tell R to ignore SIGPIPE otherwise it can raise an error
       and get us into deep trouble */
    while (i < len) {
		int n = srv->send(c, buf + i, len - i);
		if (n < 1) {
			return -1;
		}
		i += n;
    }
    return 0;
}

/* sends HTTP/x.x plus the text (which should be of the form " XXX ...") */
static int send_http_response(args_t *c, const char *text) {
    char buf[96];
	server_t *srv = c->srv;
    const char *s = HTTP_SIG(c);
    int l = strlen(text), res;
    /* reduce the number of packets by sending the payload en-block from buf */
    if (l < sizeof(buf) - 10) {
		strcpy(buf, s);
		strcpy(buf + 8, text);
		return send_response(c, buf, l + 8);
    }
    res = srv->send(c, s, 8);
    if (res < 8) return -1;
    return send_response(c, text, strlen(text));
}

/* decode URI in place (decoding never expands) */
static void uri_decode(char *s)
{
    char *t = s;
    while (*s) {
		if (*s == '+') { /* + -> SPC */
			*(t++) = ' '; s++;
		} else if (*s == '%') {
			unsigned char ec = 0;
			s++;
			if (*s >= '0' && *s <= '9') ec |= ((unsigned char)(*s - '0')) << 4;
			else if (*s >= 'a' && *s <= 'f') ec |= ((unsigned char)(*s - 'a' + 10)) << 4;
			else if (*s >= 'A' && *s <= 'F') ec |= ((unsigned char)(*s - 'A' + 10)) << 4;
			if (*s) s++;
			if (*s >= '0' && *s <= '9') ec |= (unsigned char)(*s - '0');
			else if (*s >= 'a' && *s <= 'f') ec |= (unsigned char)(*s - 'a' + 10);
			else if (*s >= 'A' && *s <= 'F') ec |= (unsigned char)(*s - 'A' + 10);
			if (*s) s++;
			*(t++) = (char) ec;
		} else *(t++) = *(s++);
    }
    *t = 0;
}

/* finalize a request - essentially for HTTP/1.0 it means that
 * we have to close the connection */
static void fin_request(args_t *c) {
    if (!IS_HTTP_1_1(c))
		c->attr |= CONNECTION_CLOSE;
}

/* process a request by calling the httpd() function in R */
static void process_request(args_t *c)
{
    char *query = 0, *s;
    DBG(fprintf(stderr, "process request for %p\n", (void*) c));
    if (!c || !c->url) return; /* if there is not enough to process, bail out */
	if (c->attr & WS_UPGRADE) {
		send_http_response(c, " 501 Upgrades not supported\r\nConnection: close\r\nContent-type: text/plain\r\n\r\n");
		c->attr |= CONNECTION_CLOSE; /* force close */
		return;
	}

    s = c->url;
    while (*s && *s != '?') s++; /* find the query part */
    if (*s) {
		*(s++) = 0;
		query = s;
    }
    uri_decode(c->url); /* decode the path part */
	
	fprintf(stderr, "URL: '%s', query: '%s'\n", c->url, query);
	
	{ /* SKS: all requests require realm */
		/* parse possible query strings */
		char *token = 0, *realm = 0, *user = 0, *pwd = 0, *module = 0, *qc = query;
		while (qc && *qc) {
			const char *qn = (const char *)qc;
			char *qv;
			while (*qc >= 'a' && * qc <= 'z')
				qc++;
			if (*qc != '=') /* stop parsing if it doesn't match [a-z]+= */
				break;
			*(qc++) = 0; /* replace = with NUL */
			qv = qc;
			qc = strchr(qv, '&');
			if (qc)
				*(qc++) = 0; /* replace & with NUL otherwise we are already at the end */
			uri_decode(qv);
			if (!strcmp(qn, "token"))
				token = qv;
			else if (!strcmp(qn, "realm"))
				realm = qv;
			else if (!strcmp(qn, "user"))
				user = qv;
			else if (!strcmp(qn, "pwd"))
				pwd = qv;
			else if (!strcmp(qn, "module"))
				module = qv;
			fprintf(stderr, "%s: '%s'\n", qn, qv);
		}
		
		if (!strcmp(c->url, "/version")) { /* we don't support group keys, so API version 1.3 */
			send_http_response(c, " 200 OK\r\nContent-type:text/plain\r\nContent-length: 4\r\n\r\n1.3\n");
			fin_request(c);
			return;
		}

		fprintf(stderr, "realm='%s'\n", realm ? realm : "<NULL>");
		if (!realm) {
			send_http_response(c, " 400 missing realm\r\nContent-length: 0\r\nContent-type: text/plain\r\n\r\n");
			fin_request(c);
			return;
		}

		if (!strcmp(c->url, "/valid")) { /* token 200, ((OK|SUPERCEDED)\n<user>\n<auth>\n) | NO */
			const char *res = token_op(token, realm, TO_INFO);
			if (res) {
				char buf[256];
				snprintf(buf, 256, " 200 OK\r\nContent-type: text/plain\r\nContent-length: %d\r\n\r\n", (int) strlen(res));
				send_http_response(c, buf);
				send_response(c, res, strlen(res));
			} else {
				send_http_response(c, " 200 OK\r\nContent-type:text/plain\r\nContent-length: 3\r\n\r\nNO\n");
			}
			fin_request(c);
			return;
		}
		
		if (!strcmp(c->url, "/replace")) { /* token 200 <new-token>\n<user>\n<auth> | 403 */
			const char *res = token_op(token, realm, TO_REPLACE);
			if (res) {
				char buf[256];
				snprintf(buf, 256, " 200 OK\r\nContent-type: text/plain\r\nContent-length: %d\r\n\r\n", (int)strlen(res));
				send_http_response(c, buf);
				send_response(c, res, strlen(res));
			} else {
				send_http_response(c, " 403 Invalid token\r\nContent-type:text/plain\r\nContent-length: 0\r\n\r\n");
			}
			fin_request(c);
			return;
		}
		
		if (!strcmp(c->url, "/revoke")) { /* token 200 OK | INVALID */
			const char *res = token_op(token, realm, TO_REVOKE);
			send_http_response(c, res ?
							   " 200 OK\r\nContent-type: text/plain\r\nContent-length: 3\r\n\r\nOK\n" :
							   " 200 OK\r\nContent-type: text/plain\r\nContent-length: 8\r\n\r\nINVALID\n");
			fin_request(c);
			return;
		}
		
		if (!strcmp(c->url, "/get_key") || !strcmp(c->url, "/gen_key")) { /* token 200 <empty> or <key(512-bit hex)> */
			const char *res = token_op(token, realm, c->url[3] == 't' ? TO_GET_KEY : TO_GEN_KEY);
			if (res) {
				char buf[256];
				snprintf(buf, 256, " 200 OK\r\nContent-type: text/plain\r\nContent-length: %d\r\n\r\n", (int)strlen(res));
				send_http_response(c, buf);
				send_response(c, res, strlen(res));
			} else {
				send_http_response(c, " 403 Invalid token\r\nContent-type:text/plain\r\nContent-length: 0\r\n\r\n");
			}
			fin_request(c);
			return;
		}
		
		if (!strcmp(c->url, "/stored_token")) { /* user token 200 <token>\n<user>\nstored\n */
			const char *res = store_token(token, realm, user, "stored");
			if (!res) {
				send_http_response(c, " 403 Storing not allowed\r\nContent-type:text/plain\r\nContent-length: 0\r\n\r\n");
			} else {
				char buf[256];
				snprintf(buf, 256, " 200 OK\r\nContent-type: text/plain\r\nContent-length: %d\r\n\r\n", (int)strlen(res));
				send_http_response(c, buf);
				send_response(c, res, strlen(res));
			}
			fin_request(c);
			return;
		}

		if (!strcmp(c->url, "/auth_token") || !strcmp(c->url, "/pam_token")) { /* user pwd [module] 200 <token>\n<user>\nauth/<module> */
			/* NOTE: there is a difference - pam_token uses "pam" as module, auth_token uses "auth/<module>" */
			if (c->url[1] == 'p')
				module = "pam";
			if (!module)
				module = DEFAULT_AUTH_MODULE;
			if (!auth_module(realm, user, pwd, module)) {
				send_http_response(c, " 403 Authentication failed\r\nContent-type:text/plain\r\nContent-length: 0\r\n\r\n");
			} else {
				char new_token[64];
				if (!gen_token(new_token, sizeof(new_token))) {
					send_http_response(c, " 501 Failed to generate token\r\nContent-type:text/plain\r\nContent-length: 0\r\n\r\n");
				} else {
					const char *res = store_token(token, realm, user, module);
					if (!res) {
						send_http_response(c, " 403 Storing not allowed\r\nContent-type:text/plain\r\nContent-length: 0\r\n\r\n");
					} else {
						char buf[256];
						snprintf(buf, 256, " 200 OK\r\nContent-type: text/plain\r\nContent-length: %d\r\n\r\n", (int)strlen(res));
						send_http_response(c, buf);
						send_response(c, res, strlen(res));
					}
				}
			}
			fin_request(c);
			return;
		}
	}
	send_http_response(c, " 404 Entry not found\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-length: 0\r\n\r\n");
	fin_request(c);
}

static void http_close(args_t *arg) {
	closesocket(arg->s);
	arg->s = -1;
}

/* this function is called to fetch new data from the client
 * connection socket and process it */
static void http_input_iteration(args_t *c) {
    int n;
	server_t *srv = c->srv;
	
    DBG(printf("worker_input_handler, data=%p\n", (void*) c));
    if (!c) return;
	
    DBG(printf("input handler for worker %p (sock=%d, part=%d, method=%d, line_pos=%d)\n", (void*) c, (int)c->s, (int)c->part, (int)c->method, (int)c->line_pos));
	
    /* FIXME: there is one edge case that is not caught on unix: if
     * recv reads two or more full requests into the line buffer then
     * this function exits after the first one, but input handlers may
     * not trigger, because there may be no further data. It is not
     * trivial to fix, because just checking for a full line at the
     * beginning and not calling recv won't trigger a new input
     * handler. However, under normal circumstance this should not
     * happen, because clients should wait for the response and even
     * if they don't it's unlikely that both requests get combined
     * into one packet. */
    if (c->part < PART_BODY) {
		char *s = c->line_buf;
		n = srv->recv(c, c->line_buf + c->line_pos, LINE_BUF_SIZE - c->line_pos - 1);
		DBG(printf("[recv n=%d, line_pos=%d, part=%d]\n", n, c->line_pos, (int)c->part));
		if (n < 0) { /* error, scrape this worker */
			http_close(c);
			return;
		}
		if (n == 0) { /* connection closed -> try to process and then remove */
			process_request(c);
			http_close(c);
			return;
		}
		c->line_pos += n;
		c->line_buf[c->line_pos] = 0;
		DBG(printf("in buffer: {%s}\n", c->line_buf));
		while (*s) {
			/* ok, we have genuine data in the line buffer */
			if (s[0] == '\n' || (s[0] == '\r' && s[1] == '\n')) { /* single, empty line - end of headers */
				/* --- check request validity --- */
				DBG(printf(" end of request, moving to body\n"));
				if (!(c->attr & HTTP_1_0) && !(c->attr & HOST_HEADER)) { /* HTTP/1.1 mandates Host: header */
					send_http_response(c, " 400 Bad Request (Host: missing)\r\nConnection: close\r\n\r\n");
					http_close(c);
					return;
				}
				if (c->attr & CONTENT_LENGTH && c->content_length) {
					if (c->content_length < 0 ||  /* we are parsing signed so negative numbers are bad */
						c->content_length > 2147483640 || /* R will currently have issues with body around 2Gb or more, so better to not go there */
						!(c->body = (char*) malloc(c->content_length + 1 /* allocate an extra termination byte */ ))) {
						send_http_response(c, " 413 Request Entity Too Large (request body too big)\r\nConnection: close\r\n\r\n");
						http_close(c);
						return;
					}
				}
				c->body_pos = 0;
				c->part = PART_BODY;
				if (s[0] == '\r') s++;
				s++;
				/* move the body part to the beginning of the buffer */
				c->line_pos -= s - c->line_buf;
				memmove(c->line_buf, s, c->line_pos);
				/* GET/HEAD or no content length mean no body */
				if (c->method == METHOD_GET || c->method == METHOD_HEAD ||
					!(c->attr & CONTENT_LENGTH) || c->content_length == 0) {
					if ((c->attr & CONTENT_LENGTH) && c->content_length > 0) {
						send_http_response(c, " 400 Bad Request (GET/HEAD with body)\r\n\r\n");
						http_close(c);
						return;
					}
					process_request(c);
					if (c->attr & CONNECTION_CLOSE) {
						http_close(c);
						return;
					}
					/* keep-alive - reset the worker so it can process a new request */
					if (c->url) { free(c->url); c->url = NULL; }
					if (c->body) { free(c->body); c->body = NULL; }
					if (c->content_type) { free(c->content_type); c->content_type = NULL; }
					if (c->headers) { free_buffer(c->headers); c->headers = NULL; }
					c->body_pos = 0;
					c->method = 0;
					c->part = PART_REQUEST;
					c->attr = 0;
					c->content_length = 0;
					return;
				}
				/* copy body content (as far as available) */
				c->body_pos = (c->content_length < c->line_pos) ? c->content_length : c->line_pos;
				if (c->body_pos) {
					memcpy(c->body, c->line_buf, c->body_pos);
					c->line_pos -= c->body_pos; /* NOTE: we are NOT moving the buffer since non-zero left-over causes connection close */
				}
				/* POST will continue into the BODY part */
				break;
			}
			{
				char *bol = s;
				while (*s && *s != '\r' && *s != '\n') s++;
				if (!*s) { /* incomplete line */
					if (bol == c->line_buf) {
						if (c->line_pos < LINE_BUF_SIZE) /* one, incomplete line, but the buffer is not full yet, just return */
							return;
						/* the buffer is full yet the line is incomplete - we're in trouble */
						send_http_response(c, " 413 Request entity too large\r\nConnection: close\r\n\r\n");
						http_close(c);
						return;
					}
					/* move the line to the begining of the buffer for later requests */
					c->line_pos -= bol - c->line_buf;
					memmove(c->line_buf, bol, c->line_pos);
					return;
				} else { /* complete line, great! */
					if (*s == '\r') *(s++) = 0;
					if (*s == '\n') *(s++) = 0;
					DBG(printf("complete line: {%s}\n", bol));
					if (c->part == PART_REQUEST) {
						/* --- process request line --- */
						unsigned int rll = strlen(bol); /* request line length */
						char *url = strchr(bol, ' ');
						if (!url || rll < 14 || strncmp(bol + rll - 9, " HTTP/1.", 8)) { /* each request must have at least 14 characters [GET / HTTP/1.0] and have HTTP/1.x */
							send_response(c, "HTTP/1.0 400 Bad Request\r\n\r\n", 28);
							http_close(c);
							return;
						}
						url++;
						if (!strncmp(bol + rll - 3, "1.0", 3)) c->attr |= HTTP_1_0;
						if (!strncmp(bol, "GET ", 4))  c->method = METHOD_GET;
						if (!strncmp(bol, "POST ", 5)) c->method = METHOD_POST;
						if (!strncmp(bol, "HEAD ", 5)) c->method = METHOD_HEAD;
						{
#ifdef USE_HEADERS
							char *mend = url - 1;
							/* we generate a header with the method so it can be passed to the handler */
							if (!c->headers)
								c->headers = alloc_buffer(1024, NULL);
							/* make sure it fits */
							if (c->headers->size - c->headers->length >= 18 + (mend - bol)) {
								if (!c->method) c->method = METHOD_OTHER;
								/* add "Request-Method: xxx" */
								memcpy(c->headers->data + c->headers->length, "Request-Method: ", 16);
								c->headers->length += 16;
								memcpy(c->headers->data + c->headers->length, bol, mend - bol);
								c->headers->length += mend - bol;	
								c->headers->data[c->headers->length++] = '\n';
							}
#endif
						}
						if (!c->method) {
							send_http_response(c, " 501 Invalid or unimplemented method\r\n\r\n");
							http_close(c);
							return;
						}
						bol[strlen(bol) - 9] = 0;
						c->url = strdup(url);
						c->part = PART_HEADER;
						DBG(printf("parsed request, method=%d, URL='%s'\n", (int)c->method, c->url));
					} else if (c->part == PART_HEADER) {
						/* --- process headers --- */
						char *k = bol;
#ifdef USE_HEADERS
						if (!c->headers)
							c->headers = alloc_buffer(1024, NULL);
						if (c->headers) { /* record the header line in the buffer */
							int l = strlen(bol);
							if (l) { /* this should be really always true */
								if (c->headers->length + l + 1 > c->headers->size) { /* not enough space? */
									int fits = c->headers->size - c->headers->length;
									int needs = 2048;
									if (fits) {
										memcpy(c->headers->data + c->headers->length, bol, fits);
										c->headers->length += fits;
									}
									while (l + 1 - fits >= needs) needs <<= 1;
									if (alloc_buffer(needs, c->headers)) {
										c->headers = c->headers->next;
										memcpy(c->headers->data, bol + fits, l - fits);
										c->headers->length = l - fits;
										c->headers->data[c->headers->length++] = '\n';
									}
								} else {
									memcpy(c->headers->data + c->headers->length, bol, l);
									c->headers->length += l;	
									c->headers->data[c->headers->length++] = '\n';
								}
							}
						}
#endif
						while (*k && *k != ':') {
							if (*k >= 'A' && *k <= 'Z')
								*k |= 0x20;
							k++;
						}
						if (*k == ':') {
							*(k++) = 0;
							while (*k == ' ' || *k == '\t') k++;
							DBG(printf("header '%s' => '%s'\n", bol, k));
							if (!strcmp(bol, "upgrade") && !strcmp(k, "websocket"))
								c->attr |= WS_UPGRADE;
							if (!strcmp(bol, "content-length")) {
								c->attr |= CONTENT_LENGTH;
								c->content_length = atol(k);
							}
							if (!strcmp(bol, "content-type")) {
								char *l = k;
								while (*l) { if (*l >= 'A' && *l <= 'Z') *l |= 0x20; l++; }
								c->attr |= CONTENT_TYPE;
								if (c->content_type) free(c->content_type);
								c->content_type = strdup(k);
								if (!strncmp(k, "application/x-www-form-urlencoded", 33))
									c->attr |= CONTENT_FORM_UENC;
							}
							if (!strcmp(bol, "host"))
								c->attr |= HOST_HEADER;
							if (!strcmp(bol, "connection")) {
								char *l = k;
								while (*l) { if (*l >= 'A' && *l <= 'Z') *l |= 0x20; l++; }
								if (!strncmp(k, "close", 5))
									c->attr |= CONNECTION_CLOSE;
							}
							DBG(fprintf(stderr, " [attr = %x]\n", c->attr));
						}
					}
				}
			}
		}
		if (c->part < PART_BODY) {
			/* we end here if we processed a buffer of exactly one line */
			c->line_pos = 0;
			return;
		}
    }
    if (c->part == PART_BODY && c->body) { /* BODY  - this branch always returns */
		if (c->body_pos < c->content_length) { /* need to receive more ? */
			DBG(printf("BODY: body_pos=%d, content_length=%ld\n", c->body_pos, c->content_length));
			n = srv->recv(c, c->body + c->body_pos, c->content_length - c->body_pos);
			DBG(printf("      [recv n=%d - had %u of %lu]\n", n, c->body_pos, c->content_length));
			c->line_pos = 0;
			if (n < 0) { /* error, scrap this worker */
				http_close(c);
				return;
			}
			if (n == 0) { /* connection closed -> try to process and then remove */
				process_request(c);
				http_close(c);
				return;
			}
			c->body_pos += n;
		}
		if (c->body_pos == c->content_length) { /* yay! we got the whole body */
			process_request(c);
			if (c->attr & CONNECTION_CLOSE || c->line_pos) { /* we have to close the connection if there was a double-hit */
				http_close(c);
				return;
			}
			/* keep-alive - reset the worker so it can process a new request */
			if (c->url) { free(c->url); c->url = NULL; }
			if (c->body) { free(c->body); c->body = NULL; }
			if (c->content_type) { free(c->content_type); c->content_type = NULL; }
			if (c->headers) { free_buffer(c->headers); c->headers = NULL; }
			c->line_pos = 0; c->body_pos = 0;
			c->method = 0;
			c->part = PART_REQUEST;
			c->attr = 0;
			c->content_length = 0;
			return;
		}
    }
	
    /* we enter here only if recv was used to leave the headers with no body */
    if (c->part == PART_BODY && !c->body) {
		char *s = c->line_buf;
		if (c->line_pos > 0) {
			if ((s[0] != '\r' || s[1] != '\n') && (s[0] != '\n')) {
				send_http_response(c, " 411 length is required for non-empty body\r\nConnection: close\r\n\r\n");
				http_close(c);
				return;
			}
			/* empty body, good */
			process_request(c);
			if (c->attr & CONNECTION_CLOSE) {
				http_close(c);
				return;
			} else { /* keep-alive */
				int sh = 1;
				if (s[0] == '\r') sh++;
				if (c->line_pos <= sh)
					c->line_pos = 0;
				else { /* shift the remaining buffer */
					memmove(c->line_buf, c->line_buf + sh, c->line_pos - sh);
					c->line_pos -= sh;
				}
				/* keep-alive - reset the worker so it can process a new request */
				if (c->url) { free(c->url); c->url = NULL; }
				if (c->body) { free(c->body); c->body = NULL; }
				if (c->content_type) { free(c->content_type); c->content_type = NULL; }
				if (c->headers) { free_buffer(c->headers); c->headers = NULL; }
				c->body_pos = 0;
				c->method = 0;
				c->part = PART_REQUEST;
				c->attr = 0;
				c->content_length = 0;
				return;
			}
		}
		n = srv->recv(c, c->line_buf + c->line_pos, LINE_BUF_SIZE - c->line_pos - 1);
		if (n < 0) { /* error, scrap this worker */
			http_close(c);
			return;
		}
		if (n == 0) { /* connection closed -> try to process and then remove */
			process_request(c);
			http_close(c);
			return;
		}
		if ((s[0] != '\r' || s[1] != '\n') && (s[0] != '\n')) {
			send_http_response(c, " 411 length is required for non-empty body\r\nConnection: close\r\n\r\n");
			http_close(c);
			return;
		}
    }
}

static void HTTP_connected(void *parg) {
	args_t *arg = (args_t*) parg;

	if (prepare_child(arg) != 0) { /* parent or error */
		free(arg);
		return;
	}

	if (!(arg->line_buf = (char*) malloc(LINE_BUF_SIZE))) {
		RSEprintf("ERROR: unable to allocate line buffer\n");
		free(arg);
		return;
	}

	if ((arg->srv->flags & SRV_TLS) && shared_tls(0))
		add_tls(arg, shared_tls(0), 1);

	while (arg->s != -1)
		http_input_iteration(arg);

	free_args(arg);
}

server_t *create_HTTP_server(int port, int flags)
{
	server_t *srv = create_server(port, 0, 0, flags);
#ifdef RSERV_DEBUG
	fprintf(stderr, "create_HTTP_server(port = %d, flags=0x%x)\n", port, flags);
#endif
	if (srv) {
		srv->connected = HTTP_connected;
		/* srv->send_resp = */
		srv->recv      = server_recv;
		srv->send      = server_send;
		srv->fin       = server_fin;
		add_server(srv);
		return srv;
	}
	return 0;
}

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
