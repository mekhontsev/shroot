#ifndef SHROOT_IMAGE_REGISTRY_H
#define SHROOT_IMAGE_REGISTRY_H
#include "image_http.h"
#include <sqlite3.h>
struct md_oci_reference { char origin[600], repository[512], selector[140]; };
int md_oci_reference_parse(const char *,struct md_oci_reference *);
int md_registry_pull(sqlite3 *,const char *reference,int cache,int layout,
    const struct md_http_trust *,char digest[72]);
#endif
