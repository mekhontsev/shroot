#include "image_registry.h"
#include "image_io.h"
#include <mbedtls/md.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    struct md_oci_reference ref;
    assert(!md_oci_reference_parse("alpine",&ref));
    assert(!strcmp(ref.origin,"https://registry-1.docker.io"));
    assert(!strcmp(ref.repository,"library/alpine") && !strcmp(ref.selector,"latest"));
    assert(!md_oci_reference_parse("docker.io/library/alpine:3.23",&ref));
    assert(!strcmp(ref.repository,"library/alpine") && !strcmp(ref.selector,"3.23"));
    assert(!md_oci_reference_parse("ghcr.io/user/image:test-1",&ref));
    assert(!strcmp(ref.origin,"https://ghcr.io") && !strcmp(ref.repository,"user/image"));
    assert(!md_oci_reference_parse("localhost:443/project/image",&ref));
    assert(!strcmp(ref.origin,"https://localhost"));
    assert(!md_oci_reference_parse("[::1]:5000/project/image",&ref));
    const char *bad[]={"", "https://docker.io/alpine", "../image", "host/../image", "Uppercase",
        "repo:bad tag", "repo@sha512:1234", "repo@sha256:1234", "repo:tag@sha256:1234", "user//image",
        "user/.hidden", "registry.test:0/a?b", "user/image#fragment", "user/image;command", "registry.test/x:"
    };
    for (size_t i=0; i<sizeof(bad)/sizeof(*bad); ++i) assert(md_oci_reference_parse(bad[i],&ref)==-EINVAL);
    assert(md_http_same_origin("https://Example.org/a","https://example.org:443/b"));
    assert(!md_http_same_origin("https://example.org/a","https://example.org:444/a"));
    assert(!md_http_same_origin("https://example.org/a","http://example.org/a"));
    char *url=NULL;
    assert(md_http_url("https://user@example.org/",&url)==-EINVAL && !url);
    assert(md_http_url("https://example.org/#fragment",&url)==-EINVAL && !url);
    assert(!md_http_query("https://example.org/token?first=1","scope","repository:a/b:pull",&url));
    assert(!strcmp(url,"https://example.org/token?first=1&scope=repository%3Aa%2Fb%3Apull"));
    free(url);
    char hash[65];
    assert(!md_image_hash_bytes("abc",3,hash));
    assert(!strcmp(hash,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    unsigned char key[20],digest[32]; memset(key,0x0b,sizeof(key));
    assert(!mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),key,sizeof(key),
        (const unsigned char *)"Hi There",8,digest));
    const unsigned char expected[]={0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};
    assert(!memcmp(digest,expected,sizeof(expected)));
    return 0;
}
