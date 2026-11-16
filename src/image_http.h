#ifndef SHROOT_IMAGE_HTTP_H
#define SHROOT_IMAGE_HTTP_H
#include <stdint.h>
struct md_http;
struct md_http_trust { const char *file, *directory; };
struct md_http_response { long status; char *challenge; };
/* This owner is used only inside the native image worker. */
int md_http_open(const struct md_http_trust *, struct md_http **);
void md_http_close(struct md_http *);
int md_http_url(const char *text, char **canonical);
int md_http_same_origin(const char *, const char *);
int md_http_query(const char *url, const char *key, const char *value, char **out);
int md_http_get(struct md_http *, const char *url, const char *accept,
    const char *token_origin, const char *token, int output, uint64_t limit,
    struct md_http_response *);
#endif
