/* Copyright 2017 yiyuanzhong@gmail.com (Yiyuan Zhong)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libubox/md5.h>
#include <microhttpd.h>

#include "configure.h"
#include "iptables.h"

struct httpd {
    const char *login_url;
    const char *splash_url;
    const char *welcome_url;
    const char *favicon_url;

    char *denied_tmpl;
    char *splash_tmpl;
    char *welcome_tmpl;
    char *host_and_port;

    struct MHD_Response *favicon;
    struct MHD_Response *splash_redirect;
    struct MHD_Response *welcome_redirect;

    struct MHD_Daemon *daemon;
    struct iptables *iptables;
    const char *device;
    const char *admin;
    const char *host;
    int milliseconds;
    const char *key;
    uint16_t port;
    int socket;

}; /* struct httpd */

struct hash {
    int32_t time;
    struct in_addr ip;
    char mac[IFHWADDRLEN];
}; /* struct hash */

struct token {
    unsigned char hash[16];
    int32_t time;
}; /* struct token */

static void httpd_hmac(
        const char *key,
        const void *input,
        size_t length,
        void *output)
{
    unsigned char buffer[64];
    unsigned char hkey[64];
    size_t keylen;
    md5_ctx_t ctx;
    int i;

    keylen = strlen(key);
    if (keylen > sizeof(hkey)) {
        md5_begin(&ctx);
        md5_hash(key, keylen, &ctx);
        md5_end(hkey, &ctx);
        memset(hkey + 16, 0, sizeof(hkey) - 16);

    } else if (keylen < sizeof(hkey)) {
        memcpy(hkey, key, keylen);
        memset(hkey + keylen, 0, sizeof(hkey) - keylen);

    } else {
        memcpy(hkey, key, sizeof(hkey));
    }

    for (i = 0; i < sizeof(hkey); ++i) {
        buffer[i] = hkey[i] ^ 0x36;
        hkey[i] ^= 0x5c;
    }

    md5_begin(&ctx);
    md5_hash(buffer, sizeof(buffer), &ctx);
    md5_hash(input, length, &ctx);
    md5_end(buffer, &ctx);

    md5_begin(&ctx);
    md5_hash(hkey, sizeof(hkey), &ctx);
    md5_hash(buffer, 16, &ctx);
    md5_end(output, &ctx);
}

static int httpd_generate_token(
        char *token,
        const char *key,
        const struct sockaddr *eth,
        const struct sockaddr_in *in)
{
    static const char H[] = "0123456789abcdef";
    struct token t;
    struct hash h;
    size_t i;

    memset(&h, 0, sizeof(h));
    memcpy(h.mac, eth->sa_data, sizeof(h.mac));
    memcpy(&h.ip, &in->sin_addr, sizeof(h.ip));
    h.time = time(NULL);

    memset(&t, 0, sizeof(t));
    httpd_hmac(key, &h, sizeof(h), t.hash);

    t.time = h.time;
    for (i = 0; i < sizeof(t); ++i) {
        *token++ = H[((unsigned char *)&t)[i] / 16];
        *token++ = H[((unsigned char *)&t)[i] % 16];
    }

    *token = '\0';
    return 0;
}

static int httpd_unhex(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        return -1;
    }
}

static int httpd_check_token(
        const char *token,
        const char *key,
        const struct sockaddr *eth,
        const struct sockaddr_in *in)
{
    unsigned char hash[16];
    unsigned int hlen;
    struct token t;
    struct hash h;
    time_t now;
    size_t i;
    int high;
    int low;

    if (strlen(token) != sizeof(t) * 2) {
        return -1;
    }

    for (i = 0; i < sizeof(t); ++i) {
        high = httpd_unhex(token[i * 2 + 0]);
        low  = httpd_unhex(token[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return -1;
        }

        ((unsigned char *)&t)[i] = (unsigned char)(high * 16 + low);
    }

    memset(&h, 0, sizeof(h));
    memcpy(h.mac, eth->sa_data, sizeof(h.mac));
    memcpy(&h.ip, &in->sin_addr, sizeof(h.ip));
    h.time = t.time;

    httpd_hmac(key, &h, sizeof(h), hash);
    if (memcmp(hash, t.hash, sizeof(hash))) {
        return -1;
    }

    now = time(NULL);
    if (h.time > now || h.time + 60 <= now) {
        return -1;
    }

    return 0;
}

static int httpd_html_escape(
        char *buffer,
        size_t size,
        const char *s,
        int escape_apos)
{
    const char *p;
    size_t needed;
    char *o;

    for (needed = 0, p = s; *p; ++p) {
        switch (*p) {
        case '\'' : needed += escape_apos ? 5 : 1; break;
        case '"'  : needed += 6; break;
        case '&'  : needed += 5; break;
        case '<'  : needed += 4; break;
        case '>'  : needed += 4; break;
        default   : needed += 1; break;
        }
    }

    if (needed >= size) {
        return needed;
    }

    for (o = buffer; *s; ++s) {
        switch (*s) {
        case '"' : memcpy(o, "&quot;", 6); o += 6; break;
        case '&' : memcpy(o, "&amp;",  5); o += 5; break;
        case '<' : memcpy(o, "&lt;",   4); o += 4; break;
        case '>' : memcpy(o, "&gt;",   4); o += 4; break;
        case '\'':
            if (escape_apos) {
                memcpy(o, "&#39;", 5);
                o += 5;
                break;
            }
        default  : *o++ = *s; break;
        };
    }

    return needed;
}

#define CHECK(pos, buffer) if ((pos) >= (int)sizeof(buffer)) return MHD_NO
static struct MHD_Response *httpd_create_standard_response(
        int status_code,
        const char *extra,
        int close)
{
    struct MHD_Response *r;
    const char *status;
    char buffer[8192];
    int pos;

    switch (status_code) {
    case MHD_HTTP_FOUND:
        status = "Found";
        break;
    case MHD_HTTP_BAD_REQUEST:
        status = "Bad Request";
        break;
    case MHD_HTTP_FORBIDDEN:
        status = "Forbidden";
        break;
    case MHD_HTTP_NOT_FOUND:
        status = "Not Found";
        break;
    case MHD_HTTP_INTERNAL_SERVER_ERROR:
        status = "Internal Server Error";
        break;
    default:
        abort();
    }

    pos = snprintf(buffer, sizeof(buffer),
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n"
            "<title>%d %s</title>\n"
            "</head><body>\n"
            "<h1>%s</h1>\n"
            "<p>",
            status_code, status, status);
    CHECK(pos, buffer);

    switch (status_code) {
    case MHD_HTTP_FOUND:
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                "The document has moved <a href=\"");
        CHECK(pos, buffer);
        pos += httpd_html_escape(buffer + pos, sizeof(buffer) - pos, extra, 1);
        CHECK(pos, buffer);
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\" here</a>.");
        CHECK(pos, buffer);
        break;

    case MHD_HTTP_BAD_REQUEST:
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                "Your browser sent a request that this server could not "
                "understand.<br />\n");
        CHECK(pos, buffer);
        break;

    case MHD_HTTP_FORBIDDEN:
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                "You don't have permission to access ");
        CHECK(pos, buffer);
        pos += httpd_html_escape(buffer + pos, sizeof(buffer) - pos, extra, 0);
        CHECK(pos, buffer);
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                "\n on this server.<br />");
        CHECK(pos, buffer);
        break;

    case MHD_HTTP_NOT_FOUND:
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                "The requested URL ");
        CHECK(pos, buffer);
        pos += httpd_html_escape(buffer + pos, sizeof(buffer) - pos, extra, 0);
        CHECK(pos, buffer);
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                " was not found on this server.");
        CHECK(pos, buffer);
        break;

    case MHD_HTTP_INTERNAL_SERVER_ERROR:
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                "The server encountered an internal error or\n"
                "misconfiguration and was unable to complete\n"
                "your request.</p>\n"
                "<p>Please contact the server administrator at \n"
                " ");
        CHECK(pos, buffer);
        pos += httpd_html_escape(buffer + pos, sizeof(buffer) - pos, extra, 0);
        CHECK(pos, buffer);
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                " to inform them of the time this error occurred,\n"
                " and the actions you performed just before this error.</p>\n"
                "<p>More information about this error may be available\n"
                "in the server error log.");
        CHECK(pos, buffer);
        break;

    default:
        abort();
    }

    pos += snprintf(buffer + pos, sizeof(buffer) - pos,
            "</p>\n"
            "</body></html>\n");
    CHECK(pos, buffer);

    r = MHD_create_response_from_buffer(pos, buffer, MHD_RESPMEM_MUST_COPY);
    if (!r) {
        return NULL;
    }

    if (MHD_add_response_header(r, MHD_HTTP_HEADER_SERVER,
                "Apache") != MHD_YES ||
        MHD_add_response_header(r, MHD_HTTP_HEADER_CONTENT_TYPE,
                "text/html; charset=iso-8859-1") != MHD_YES) {

        MHD_destroy_response(r);
        return NULL;
    }

    if (close) {
        if (MHD_add_response_header(r, MHD_HTTP_HEADER_CONNECTION, "close") != MHD_YES) {
            MHD_destroy_response(r);
            return NULL;
        }
    }

    return r;
}

static int httpd_standard_response(
        struct MHD_Connection *connection,
        int status_code,
        const char *extra,
        int close)
{
    struct MHD_Response *r;
    int ret;

    r = httpd_create_standard_response(status_code, extra, close);
    if (!r) {
        return MHD_NO;
    }

    ret =  MHD_queue_response(connection, status_code, r);
    MHD_destroy_response(r);
    return ret;
}

static int httpd_error(struct MHD_Connection *connection, const char *admin)
{
    return httpd_standard_response(
            connection,
            MHD_HTTP_INTERNAL_SERVER_ERROR,
            admin,
            1);
}

static struct MHD_Response *httpd_create_redirect_response(const char *url)
{
    struct MHD_Response *r;

    r = httpd_create_standard_response(MHD_HTTP_FOUND, url, 0);
    if (!r) {
        return NULL;
    }

    if (MHD_add_response_header(r, MHD_HTTP_HEADER_LOCATION, url) != MHD_YES) {
        MHD_destroy_response(r);
        return NULL;
    }

    return r;
}

static char *httpd_check_buffer(char *buffer, size_t *size, char **q, size_t n)
{
    char *temp;
    size_t pos;

    pos = *q - buffer;
    if (pos + n < *size) {
        return buffer;
    }

    while (pos + n >= *size) {
        *size *= 2;
    }

    temp = (char *)realloc(buffer, *size);
    if (!temp) {
        free(buffer);
        return NULL;
    }

    *q = temp + pos;
    return temp;
}

static char *httpd_apply_template(
        const char *tmpl,
        const char *keys[],
        const char *values[])
{
    const char *last;
    const char *p;
    char *buffer;
    size_t vlen;
    size_t size;
    size_t pos;
    char *q;
    int i;

    size = strlen(tmpl) + 1024;
    buffer = (char *)malloc(size);
    if (!buffer) {
        return NULL;
    }

    pos = 0;
    last = NULL;
    for (p = tmpl, q = buffer; *p; ++p) {
        if (*p == '@') {
            if (!last) {
                last = p + 1;
                continue;
            }

            for (i = 0; keys[i]; ++i) {
                if (memcmp(keys[i], last, p - last) ||
                    keys[i][p - last] != '\0'       ){

                    continue;
                }

                vlen = strlen(values[i]);
                buffer = httpd_check_buffer(buffer, &size, &q, vlen);
                if (!buffer) {
                    return NULL;
                }

                memcpy(q, values[i], vlen);
                last = NULL;
                pos += vlen;
                q += vlen;
                break;
            }

            if (last) {
                free(buffer);
                return NULL;
            }

        } else if (!last) {
            buffer = httpd_check_buffer(buffer, &size, &q, 1);
            if (!buffer) {
                return NULL;
            }

            *q++ = *p;
            ++pos;
        }
    }

    if (last) {
        free(buffer);
        return NULL;
    }

    *q = '\0';
    return buffer;
}

static int httpd_handle_denied(
        struct httpd *h,
        const struct sockaddr *eth,
        const struct sockaddr_in *in,
        struct MHD_Connection *connection)
{
    struct MHD_Response *r;
    char *buffer;

    const char *keys[] = { NULL };
    const char *values[] = { NULL };

    if (iptables_deny(h->iptables, eth, in)) {
        return httpd_error(connection, h->admin);
    }

    if (!h->denied_tmpl) {
        return httpd_standard_response(
                connection,
                MHD_HTTP_FORBIDDEN,
                h->login_url,
                0);
    }

    buffer = httpd_apply_template(h->denied_tmpl, keys, values);
    if (!buffer) {
        return httpd_error(connection, h->admin);
    }

    r = MHD_create_response_from_buffer(
            strlen(buffer),
            buffer,
            MHD_RESPMEM_MUST_COPY);

    free(buffer);
    if (!r) {
        return httpd_error(connection, h->admin);
    }

    if (MHD_queue_response(connection, MHD_HTTP_OK, r) != MHD_YES) {
        MHD_destroy_response(r);
        return httpd_error(connection, h->admin);
    }

    MHD_destroy_response(r);
    return MHD_YES;
}

static int httpd_handle_authenticated(
        struct httpd *h,
        const struct sockaddr *eth,
        const struct sockaddr_in *in,
        struct MHD_Connection *connection)
{
    if (iptables_allow(h->iptables, eth, in, h->milliseconds)) {
        return httpd_error(connection, h->admin);
    }

    return MHD_queue_response(connection, MHD_HTTP_FOUND, h->welcome_redirect);
}

static int httpd_handle_welcome(
        struct httpd *h,
        const struct sockaddr *eth,
        const struct sockaddr_in *in,
        struct MHD_Connection *connection)
{
    struct MHD_Response *r;
    char *buffer;

    const char *keys[] = { NULL };
    const char *values[] = { NULL };

    if (iptables_verify(h->iptables, eth, in)) {
        return MHD_queue_response(connection, MHD_HTTP_FOUND, h->splash_redirect);
    }

    buffer = httpd_apply_template(h->welcome_tmpl, keys, values);
    if (!buffer) {
        return httpd_error(connection, h->admin);
    }

    r = MHD_create_response_from_buffer(
            strlen(buffer),
            buffer,
            MHD_RESPMEM_MUST_COPY);

    free(buffer);
    if (!r) {
        return httpd_error(connection, h->admin);
    }

    if (MHD_queue_response(connection, MHD_HTTP_OK, r) != MHD_YES) {
        MHD_destroy_response(r);
        return httpd_error(connection, h->admin);
    }

    MHD_destroy_response(r);
    return MHD_YES;
}

static int httpd_handle_splash(
        struct httpd *h,
        const struct sockaddr *eth,
        const struct sockaddr_in *in,
        struct MHD_Connection *connection)
{
    static const char *keys[] = { "URL", NULL };
    struct MHD_Response *r;
    const char *values[2];
    char escaped[256];
    char token[64];
    char url[256];
    char *buffer;
    int ret;

    if (httpd_generate_token(token, h->key, eth, in)) {
        return httpd_error(connection, h->admin);
    }

    ret = snprintf(url, sizeof(url), "http://%s%s%s", h->host, h->login_url, token);
    if (ret < 0 || (size_t)ret >= sizeof(url)) {
        return httpd_error(connection, h->admin);
    }

    ret = httpd_html_escape(escaped, sizeof(escaped), url, 1);
    if (ret < 0 || (size_t)ret >= sizeof(escaped)) {
        return httpd_error(connection, h->admin);
    }

    escaped[ret] = '\0';
    values[0] = escaped;
    values[1] = NULL;

    buffer = httpd_apply_template(h->splash_tmpl, keys, values);
    if (!buffer) {
        return httpd_error(connection, h->admin);
    }

    r = MHD_create_response_from_buffer(
            strlen(buffer),
            buffer,
            MHD_RESPMEM_MUST_COPY);

    free(buffer);
    if (!r) {
        return httpd_error(connection, h->admin);
    }

    if (MHD_queue_response(connection, MHD_HTTP_OK, r) != MHD_YES) {
        MHD_destroy_response(r);
        return httpd_error(connection, h->admin);
    }

    MHD_destroy_response(r);
    return MHD_YES;
}

static int httpd_handle_login(
        struct httpd *h,
        const char *token,
        const struct sockaddr *eth,
        const struct sockaddr_in *in,
        struct MHD_Connection *connection)
{
    if (httpd_check_token(token, h->key, eth, in)) {
        return httpd_handle_denied(h, eth, in, connection);
    } else {
        return httpd_handle_authenticated(h, eth, in, connection);
    }
}

static int httpd_handler(
        void *cls,
        struct MHD_Connection *connection,
        const char *url,
        const char *method,
        const char *version,
        const char *upload_data,
        size_t *upload_data_size,
        void **con_cls)
{
    const union MHD_ConnectionInfo *c;
    const struct sockaddr *addr;
    struct arpreq arp;
    const char *host;
    struct httpd *h;

    (void)method;
    (void)upload_data_size;
    (void)upload_data;
    (void)con_cls;

    host = MHD_lookup_connection_value(
            connection,
            MHD_HEADER_KIND,
            MHD_HTTP_HEADER_HOST);

    h = (struct httpd *)cls;
    if (strcmp(version, MHD_HTTP_VERSION_1_1) == 0) {
        if (!host) {
            return httpd_standard_response(connection, MHD_HTTP_BAD_REQUEST, NULL, 1);
        }

    } else if (strcmp(version, MHD_HTTP_VERSION_1_0)) {
        return httpd_standard_response(connection, MHD_HTTP_BAD_REQUEST, NULL, 1);
    }

    c = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (!c) {
        return httpd_error(connection, h->admin);
    }

    addr = *(const struct sockaddr **)c;
    if (addr->sa_family != AF_INET) {
        return httpd_standard_response(connection, MHD_HTTP_FORBIDDEN, url, 0);
    }

    memset(&arp, 0, sizeof(arp));
    strcpy(arp.arp_dev, h->device);
    memcpy(&arp.arp_pa, addr, sizeof(*addr));

    if (ioctl(h->socket, SIOCGARP, &arp)) {
        return httpd_standard_response(connection, MHD_HTTP_FORBIDDEN, url, 0);
    }

    if (strcmp(url, h->welcome_url) == 0) {
        return httpd_handle_welcome(
                h,
                &arp.arp_ha,
                (const struct sockaddr_in *)addr,
                connection);

    } else if (strncmp(url, h->login_url, strlen(h->login_url)) == 0) {
        return httpd_handle_login(
                h,
                url + strlen(h->login_url),
                &arp.arp_ha,
                (const struct sockaddr_in *)addr,
                connection);

    } else if (strcmp(url, h->favicon_url) == 0) {
        if (h->favicon) {
            return MHD_queue_response(connection, MHD_HTTP_OK, h->favicon);
        }
    }

    return httpd_handle_splash(
            h,
            &arp.arp_ha,
            (const struct sockaddr_in *)addr,
            connection);
}

static char *httpd_read_file(const char *filename, size_t *size)
{
    char *buffer;
    FILE *fp;
    long s;

    fp = fopen(filename, "rb");
    if (!fp) {
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) < 0 ||
        (s = ftell(fp)) < 0        ){

        fclose(fp);
        return NULL;
    }

    rewind(fp);
    buffer = (char *)malloc(s + 1);
    if (!buffer) {
        fclose(fp);
        return NULL;
    }

    if (fread(buffer, 1, s, fp) != (size_t)s) {
        fclose(fp);
        free(buffer);
        return NULL;
    }

    buffer[s] = '\0';
    fclose(fp);
    if (size) {
        *size = (size_t)s;
    }

    return buffer;
}

void httpd_stop(struct httpd *h)
{
    if (!h) {
        return;
    }

    if (h->daemon) {
        MHD_stop_daemon(h->daemon);
    }

    if (h->favicon) {
        MHD_destroy_response(h->favicon);
    }

    if (h->splash_redirect) {
        MHD_destroy_response(h->splash_redirect);
    }

    if (h->welcome_redirect) {
        MHD_destroy_response(h->welcome_redirect);
    }

    if (h->socket >= 0) {
        close(h->socket);
    }

    if (h->denied_tmpl) {
        free(h->denied_tmpl);
    }

    if (h->splash_tmpl) {
        free(h->splash_tmpl);
    }

    if (h->welcome_tmpl) {
        free(h->welcome_tmpl);
    }

    if (h->host_and_port) {
        free(h->host_and_port);
    }

    free(h);
}

struct httpd *httpd_start(
        const struct configure *c,
        struct iptables *i)
{
    unsigned int flags;
    char buffer[1024];
    struct httpd *h;
    size_t size;
    char *p;

    if (!c                              ||
        !c->device                      ||
        !c->welcome_template_filename   ||
        !c->splash_template_filename    ||
        !c->admin_email                 ||
        !c->hostname                    ||
        !c->port                        ||
        c->milliseconds <= 60000        ){

        return NULL;
    }

    h = (struct httpd *)malloc(sizeof(struct httpd));
    if (!h) {
        return NULL;
    }

    memset(h, 0, sizeof(*h));
    h->socket = -1;

    h->login_url   = "/kerberos/login/";
    h->splash_url  = "/kerberos/splash/";
    h->welcome_url = "/kerberos/welcome/";
    h->favicon_url = "/favicon.ico";

    h->key = c->key;
    h->port = c->port;
    h->host = c->hostname;
    h->device = c->device;
    h->admin = c->admin_email;

    snprintf(buffer, sizeof(buffer), "%s:%u", c->hostname, c->port);
    h->host_and_port = strdup(buffer);
    if (!h->host_and_port) {
        return httpd_stop(h), NULL;
    }

    h->welcome_tmpl = httpd_read_file(c->welcome_template_filename, NULL);
    h->splash_tmpl = httpd_read_file(c->splash_template_filename, NULL);
    if (!h->welcome_tmpl || !h->splash_tmpl) {
        return httpd_stop(h), NULL;
    }

    if (c->denied_template_filename && *c->denied_template_filename) {
        h->denied_tmpl = httpd_read_file(c->denied_template_filename, NULL);
        if (!h->denied_tmpl) {
            return httpd_stop(h), NULL;
        }
    }

    if (c->favicon_filename && *c->favicon_filename) {
        p = httpd_read_file(c->favicon_filename, &size);
        if (!p) {
            return httpd_stop(h), NULL;
        }

        h->favicon = MHD_create_response_from_buffer(
                size, p, MHD_RESPMEM_MUST_FREE);

        if (!h->favicon) {
            free(p);
            return httpd_stop(h), NULL;
        }
    }

    snprintf(buffer, sizeof(buffer), "http://%s%s", h->host, h->splash_url);
    h->splash_redirect = httpd_create_redirect_response(buffer);
    if (!h->splash_redirect) {
        return httpd_stop(h), NULL;
    }

    snprintf(buffer, sizeof(buffer), "%s", h->welcome_url);
    h->welcome_redirect = httpd_create_redirect_response(buffer);
    if (!h->welcome_redirect) {
        return httpd_stop(h), NULL;
    }

    h->socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (h->socket < 0) {
        return httpd_stop(h), NULL;
    }

    flags = MHD_USE_SELECT_INTERNALLY;
#ifndef NDEBUG
    flags |= MHD_USE_DEBUG;
#endif

    h->daemon = MHD_start_daemon(
            flags, c->port, NULL, NULL, httpd_handler, h,
            MHD_OPTION_END);

    if (!h->daemon) {
        return httpd_stop(h), NULL;
    }

    h->milliseconds = c->milliseconds;
    h->iptables = i;
    return h;
}
