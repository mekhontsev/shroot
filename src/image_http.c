#define _GNU_SOURCE
#include "image_http.h"
#include "image_io.h"
#include <curl/curl.h>
#include <curl/header.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

struct md_http { CURL *curl; const char *ca_file, *ca_directory; };
static CURLU *parse(const char *text) {
    CURLU *url=curl_url();
    if (!url) return NULL;
    char *scheme=NULL,*part=NULL;
    int r=curl_url_set(url,CURLUPART_URL,text,0);
    if (!r) r=curl_url_get(url,CURLUPART_SCHEME,&scheme,0);
    if (!r && strcasecmp(scheme,"https")) r=1;
    CURLUPart forbidden[]={CURLUPART_USER,CURLUPART_PASSWORD,CURLUPART_OPTIONS,CURLUPART_FRAGMENT};
    for (size_t i=0; !r && i<sizeof(forbidden)/sizeof(*forbidden); ++i) {
        if (!curl_url_get(url,forbidden[i],&part,0)) r=1;
        curl_free(part); part=NULL;
    }
    curl_free(scheme);
    if (r) { curl_url_cleanup(url); return NULL; }
    return url;
}
static int stringify(CURLU *url,char **out) {
    char *value=NULL;
    int r=curl_url_get(url,CURLUPART_URL,&value,CURLU_NO_DEFAULT_PORT) ? -EINVAL : 0;
    if (!r && !(*out=strdup(value))) r=-ENOMEM;
    curl_free(value); return r;
}
int md_http_url(const char *text,char **out) {
    *out=NULL;
    CURLU *url=parse(text);
    if (!url) return -EINVAL;
    int r=stringify(url,out);
    curl_url_cleanup(url); return r;
}
int md_http_same_origin(const char *a,const char *b) {
    CURLU *left=parse(a),*right=parse(b);
    int equal=left && right;
    CURLUPart fields[]={CURLUPART_HOST,CURLUPART_PORT};
    for (size_t i=0; equal && i<2; ++i) {
        char *x=NULL,*y=NULL;
        equal=!curl_url_get(left,fields[i],&x,CURLU_DEFAULT_PORT)
            && !curl_url_get(right,fields[i],&y,CURLU_DEFAULT_PORT) && !strcasecmp(x,y);
        curl_free(x); curl_free(y);
    }
    curl_url_cleanup(left); curl_url_cleanup(right); return equal;
}
int md_http_query(const char *text,const char *key,const char *value,char **out) {
    *out=NULL;
    CURLU *url=parse(text);
    if (!url) return -EINVAL;
    char *entry=NULL;
    int r=asprintf(&entry,"%s=%s",key,value)<0 ? -ENOMEM : 0;
    if (!r && curl_url_set(url,CURLUPART_QUERY,entry,CURLU_APPENDQUERY|CURLU_URLENCODE)) r=-EINVAL;
    if (!r) r=stringify(url,out);
    free(entry); curl_url_cleanup(url); return r;
}
int md_http_open(const struct md_http_trust *trust,struct md_http **out) {
    *out=NULL;
    if (curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK) return -EIO;
    struct md_http *http=calloc(1,sizeof(*http));
    if (!http) { curl_global_cleanup(); return -ENOMEM; }
    if (trust) { http->ca_file=trust->file; http->ca_directory=trust->directory; }
    if (!http->ca_file && !http->ca_directory) {
#ifdef __ANDROID__
        const char *directories[]={"/apex/com.android.conscrypt/cacerts","/system/etc/security/cacerts"};
        for (size_t i=0; i<sizeof(directories)/sizeof(*directories); ++i)
            if (!access(directories[i],R_OK|X_OK)) { http->ca_directory=directories[i]; break; }
#else
        const char *files[]={"/etc/ssl/certs/ca-certificates.crt","/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem","/etc/ssl/ca-bundle.pem"};
        for (size_t i=0; i<sizeof(files)/sizeof(*files); ++i)
            if (!access(files[i],R_OK)) { http->ca_file=files[i]; break; }
        if (!http->ca_file && !access("/etc/ssl/certs",R_OK|X_OK)) http->ca_directory="/etc/ssl/certs";
#endif
    }
    int r=0;
    if (!http->ca_file && !http->ca_directory) r=-ENOENT;
    if (!r && !(http->curl=curl_easy_init())) r=-ENOMEM;
    if (r) md_http_close(http); else *out=http;
    return r;
}
void md_http_close(struct md_http *http) {
    if (!http) return;
    curl_easy_cleanup(http->curl); free(http); curl_global_cleanup();
}
struct sink { int fd, error; uint64_t size, limit; };
static size_t write_body(char *data,size_t size,size_t count,void *opaque) {
    struct sink *sink=opaque;
    if (size && count>SIZE_MAX/size) { sink->error=-EOVERFLOW; return CURL_WRITEFUNC_ERROR; }
    size_t bytes=size*count;
    if (bytes>sink->limit-sink->size) sink->error=-EFBIG;
    if (!sink->error) sink->error=md_image_write(sink->fd,data,bytes);
    if (sink->error) return CURL_WRITEFUNC_ERROR;
    sink->size+=bytes; return bytes;
}
static int append_header(struct curl_slist **headers,const char *prefix,const char *value) {
    if (!value) return 0;
    for (const unsigned char *p=(const unsigned char *)value; *p; ++p)
        if (*p<32 || *p==127) return -EINVAL;
    char *line=NULL;
    if (asprintf(&line,"%s%s",prefix,value)<0) return -ENOMEM;
    struct curl_slist *more=curl_slist_append(*headers,line);
    free(line);
    if (!more) return -ENOMEM;
    *headers=more; return 0;
}
static int transfer_error(CURLcode code) {
    switch (code) {
    case CURLE_OK: return 0;
    case CURLE_OUT_OF_MEMORY: return -ENOMEM;
    case CURLE_OPERATION_TIMEDOUT: return -ETIMEDOUT;
    case CURLE_PEER_FAILED_VERIFICATION: case CURLE_SSL_CACERT_BADFILE: return -EACCES;
    case CURLE_FILESIZE_EXCEEDED: return -EFBIG;
    case CURLE_COULDNT_CONNECT: return -ECONNREFUSED;
    case CURLE_COULDNT_RESOLVE_HOST: return -EHOSTUNREACH;
    default: return -EIO;
    }
}
int md_http_get(struct md_http *http,const char *text,const char *accept,
        const char *origin,const char *token,int output,uint64_t limit,struct md_http_response *response) {
    *response=(struct md_http_response){0};
    if (limit>INT64_MAX || (token && !origin)) return -EINVAL;
    char *url=NULL;
    int r=md_http_url(text,&url);
    for (unsigned hop=0; !r; ++hop) {
        if (hop==10) { r=-ELOOP; break; }
        if (ftruncate(output,0) || lseek(output,0,SEEK_SET)<0) { r=-errno; break; }
        struct curl_slist *headers=NULL;
        r=append_header(&headers,"Accept: ",accept);
        if (!r && token && md_http_same_origin(origin,url)) r=append_header(&headers,"Authorization: Bearer ",token);
        struct sink sink={.fd=output,.limit=limit};
        CURL *curl=http->curl;
        curl_easy_reset(curl);
#define SET(option,value) do { if (!r) r=transfer_error(curl_easy_setopt(curl,option,value)); } while (0)
        SET(CURLOPT_URL,url);
        SET(CURLOPT_PROTOCOLS_STR,"https");
        SET(CURLOPT_REDIR_PROTOCOLS_STR,"https");
        SET(CURLOPT_FOLLOWLOCATION,0L);
        SET(CURLOPT_NOSIGNAL,1L);
        SET(CURLOPT_CONNECTTIMEOUT,30L);
        SET(CURLOPT_LOW_SPEED_TIME,60L);
        SET(CURLOPT_LOW_SPEED_LIMIT,1L);
        SET(CURLOPT_MAXFILESIZE_LARGE,(curl_off_t)limit);
        SET(CURLOPT_USERAGENT,"Shroot/" SHROOT_VERSION);
        SET(CURLOPT_HTTPHEADER,headers);
        SET(CURLOPT_HEADEROPT,(long)CURLHEADER_SEPARATE);
        SET(CURLOPT_WRITEFUNCTION,write_body);
        SET(CURLOPT_WRITEDATA,&sink);
        SET(CURLOPT_CAINFO,http->ca_file);
        SET(CURLOPT_CAPATH,http->ca_directory);
        SET(CURLOPT_SSL_VERIFYPEER,1L);
        SET(CURLOPT_SSL_VERIFYHOST,2L);
        SET(CURLOPT_HTTP_CONTENT_DECODING,0L);
#undef SET
        if (!r) {
            CURLcode code=curl_easy_perform(curl);
            r=sink.error ? sink.error : transfer_error(code);
            if (code!=CURLE_OK && !sink.error)
                fprintf(stderr,"shroot: HTTPS transfer: %s\n",curl_easy_strerror(code));
        }
        curl_slist_free_all(headers);
        if (!r) r=transfer_error(curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&response->status));
        long status=response->status;
        if (!r && (status==301 || status==302 || status==303 || status==307 || status==308)) {
            char *location=NULL,*next=NULL;
            r=transfer_error(curl_easy_getinfo(curl,CURLINFO_REDIRECT_URL,&location));
            if (!r) r=location ? md_http_url(location,&next) : -EPROTO;
            free(url); url=next;
            continue;
        }
        if (!r && status==401 && (!origin || md_http_same_origin(origin,url))) {
            struct curl_header *header=NULL;
            CURLHcode found=curl_easy_header(curl,"WWW-Authenticate",0,CURLH_HEADER,-1,&header);
            if (found==CURLHE_OK) {
                if (header->amount!=1) r=-EPROTO;
                else if (!(response->challenge=strdup(header->value))) r=-ENOMEM;
            } else if (found!=CURLHE_MISSING) r=-EPROTO;
        }
        break;
    }
    free(url); return r;
}
