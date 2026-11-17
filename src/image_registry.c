#define _GNU_SOURCE
#include "host_open.h"
#include "image_registry.h"
#include "image_oci.h"
#include "image_io.h"
#include "image_json.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

#define JSON_LIMIT (8U*1024*1024)
static const char manifest_accept[]="application/vnd.oci.image.index.v1+json, "
    "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.docker.distribution.manifest.v2+json";
static int matches(const char *text,const char *pattern) {
    regex_t regex;
    if (regcomp(&regex,pattern,REG_EXTENDED|REG_NOSUB)) return 0;
    int yes=!regexec(&regex,text,0,NULL,0);
    regfree(&regex); return yes;
}
int md_oci_reference_parse(const char *text,struct md_oci_reference *ref) {
    memset(ref,0,sizeof(*ref));
    if (!text || !*text || strlen(text)>512 || strstr(text,"://")) return -EINVAL;
    char input[513]; strcpy(input,text);
    char *selector=strchr(input,'@');
    if (selector) {
        *selector++=0;
        if (!md_image_digest_valid(selector)) return -EINVAL;
    } else {
        char *slash=strrchr(input,'/'),*colon=strrchr(input,':');
        if (colon && (!slash || colon>slash)) { *colon=0; selector=colon+1; }
        else selector="latest";
        if (!matches(selector,"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")) return -EINVAL;
    }
    strcpy(ref->selector,selector);
    char *slash=strchr(input,'/'),*repository=input,*host="registry-1.docker.io";
    if (slash) {
        *slash=0;
        if (strchr(input,'.') || strchr(input,':') || !strcmp(input,"localhost")) {
            host=input; repository=slash+1;
        } else *slash='/';
    }
    if (!strcmp(host,"docker.io") || !strcmp(host,"index.docker.io")) host="registry-1.docker.io";
    if (strspn(host,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-:[]")!=strlen(host)) return -EINVAL;
    char raw[600],*canonical=NULL;
    snprintf(raw,sizeof(raw),"https://%s/",host);
    int r=md_http_url(raw,&canonical);
    if (!r && strlen(canonical)>=sizeof(ref->origin)) r=-EINVAL;
    if (!r) {
        strcpy(ref->origin,canonical);
        size_t n=strlen(ref->origin);
        if (n && ref->origin[n-1]=='/') ref->origin[n-1]=0;
    }
    free(canonical);
    if (!r && !matches(repository,"^[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*(/[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*)*$")) r=-EINVAL;
    if (!r && snprintf(ref->repository,sizeof(ref->repository),"%s%s",
            !strcmp(host,"registry-1.docker.io") && !strchr(repository,'/') ? "library/" : "",repository)>=(int)sizeof(ref->repository)) r=-EINVAL;
    return r;
}
struct registry {
    sqlite3 *json;
    struct md_http *http;
    struct md_oci_reference reference;
    int cache;
    char *token;
};
struct download { int fd; char name[43]; };
static int download_open(struct registry *reg,struct download *out) {
    *out=(struct download){.fd=-1};
    unsigned char random[16];
    for (size_t n=0; n<sizeof(random);) {
        ssize_t got=getrandom(random+n,sizeof(random)-n,0);
        if (got<0 && errno==EINTR) continue;
        if (got<=0) return got<0 ? -errno : -EIO;
        n+=(size_t)got;
    }
    strcpy(out->name,".download-");
    for (size_t i=0; i<sizeof(random); ++i) {
        out->name[10+2*i]="0123456789abcdef"[random[i]>>4];
        out->name[11+2*i]="0123456789abcdef"[random[i]&15];
    }
    out->fd=openat(reg->cache,out->name,O_CREAT|O_EXCL|O_RDWR|O_NOFOLLOW|O_CLOEXEC,0600);
    return out->fd<0 ? -errno : 0;
}
static void download_close(struct registry *reg,struct download *download) {
    if (download->fd>=0) {
        close(download->fd); unlinkat(reg->cache,download->name,0); download->fd=-1;
    }
}
static int recover_downloads(int cache) {
    int fd=openat(cache,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (fd<0) return -errno;
    DIR *dir=fdopendir(fd);
    if (!dir) { int r=-errno; close(fd); return r; }
    int r=0;
    while (!r) {
        errno=0;
        struct dirent *entry=readdir(dir);
        if (!entry) { if (errno) r=-errno; break; }
        const char *name=entry->d_name;
        if (strlen(name)!=42 || strncmp(name,".download-",10)
                || strspn(name+10,"0123456789abcdef")!=32) continue;
        struct stat st;
        if (fstatat(cache,name,&st,AT_SYMLINK_NOFOLLOW)) r=-errno;
        else if (!S_ISREG(st.st_mode)) r=-EINVAL;
        else if (unlinkat(cache,name,0)) r=-errno;
    }
    closedir(dir); return r;
}
/* RFC 6750 challenges use quoted parameters; reject duplicates and ambiguous
 * lists rather than choosing one endpoint from attacker-controlled syntax. */
static int challenge(const char *text,char **realm,char **service) {
    *realm=*service=NULL;
    if (strncasecmp(text,"Bearer",6) || (text[6]!=' ' && text[6]!='\t')) return -ENOTSUP;
    const char *p=text+6;
    unsigned seen=0;
    int r=0;
    while (!r) {
        while (*p==' ' || *p=='\t') ++p;
        const char *begin=p;
        while (isalnum((unsigned char)*p) || *p=='_' || *p=='-') ++p;
        size_t n=(size_t)(p-begin);
        unsigned field=n==5 && !strncasecmp(begin,"realm",5) ? 1
            : n==7 && !strncasecmp(begin,"service",7) ? 2
            : n==5 && !strncasecmp(begin,"scope",5) ? 4 : 0;
        if (!field || (seen&field)) { r=-EPROTO; break; }
        seen|=field;
        while (*p==' ' || *p=='\t') ++p;
        if (*p++!='=') { r=-EPROTO; break; }
        while (*p==' ' || *p=='\t') ++p;
        if (*p++!='"') { r=-EPROTO; break; }
        char *value=malloc(strlen(p)+1);
        if (!value) { r=-ENOMEM; break; }
        size_t used=0;
        while (*p && *p!='"') {
            if (*p=='\\') ++p;
            if ((unsigned char)*p<32 || *p==127) { r=-EPROTO; break; }
            value[used++]=*p++;
        }
        value[used]=0;
        if (r || *p!='"') { free(value); r=-EPROTO; break; }
        ++p;
        if (field==1) *realm=value;
        else if (field==2) *service=value;
        else free(value);
        while (*p==' ' || *p=='\t') ++p;
        if (!*p) break;
        if (*p++!=',') { r=-EPROTO; break; }
    }
    if (!r && (!*realm || !**realm)) r=-EPROTO;
    if (r) { free(*realm); free(*service); *realm=*service=NULL; }
    return r;
}
static int status_error(long status) {
    if (status==200) return 0;
    if (status==401 || status==403) return -EACCES;
    if (status==404) return -ENOENT;
    if (status==429) return -EAGAIN;
    return -EPROTO;
}
static int authorize(struct registry *reg,const char *header) {
    char *realm=NULL,*service=NULL,*url=NULL,*next=NULL,*json=NULL,*token=NULL,*access=NULL;
    int r=challenge(header,&realm,&service);
    if (!r) r=md_http_url(realm,&url);
    if (!r && service) {
        r=md_http_query(url,"service",service,&next);
        free(url); url=next; next=NULL;
    }
    char scope[540]; snprintf(scope,sizeof(scope),"repository:%s:pull",reg->reference.repository);
    if (!r) {
        r=md_http_query(url,"scope",scope,&next);
        free(url); url=next; next=NULL;
    }
    int fd=-1;
    if (!r && (fd=(int)md_host_temporary(reg->cache,".",0600))<0) r=fd;
    struct md_http_response response={0};
    if (!r) r=md_http_get(reg->http,url,"application/json",NULL,NULL,fd,JSON_LIMIT,&response);
    if (!r) r=status_error(response.status);
    if (!r) r=md_image_read(fd,JSON_LIMIT,&json);
    if (!r) r=md_json_validate(reg->json,json,strlen(json));
    if (!r) { r=md_json_string(reg->json,json,"$.token",&token); if (r==-ENOENT) r=0; }
    if (!r) { r=md_json_string(reg->json,json,"$.access_token",&access); if (r==-ENOENT) r=0; }
    if (!r && token && access && strcmp(token,access)) r=-EPROTO;
    if (!token) { token=access; access=NULL; }
    if (!r && (!token || !*token || strlen(token)>65536)) r=-EPROTO;
    if (!r) for (const unsigned char *p=(unsigned char *)token; *p; ++p)
        if (*p<=32 || *p>=127) { r=-EPROTO; break; }
    if (!r) { free(reg->token); reg->token=token; token=NULL; }
    if (fd>=0) close(fd);
    free(response.challenge); free(realm); free(service); free(url); free(json); free(token); free(access);
    return r;
}
static int request(struct registry *reg,const char *kind,const char *id,int fd,uint64_t limit) {
    char *url=NULL;
    if (asprintf(&url,"%s/v2/%s/%s/%s",reg->reference.origin,reg->reference.repository,kind,id)<0) return -ENOMEM;
    int r=0;
    for (unsigned attempt=0; attempt<2; ++attempt) {
        struct md_http_response response={0};
        r=md_http_get(reg->http,url,manifest_accept,reg->reference.origin,reg->token,fd,limit,&response);
        int retry=!r && !attempt && response.status==401 && response.challenge;
        if (retry) r=authorize(reg,response.challenge);
        else if (!r) {
            r=status_error(response.status);
            if (r) fprintf(stderr,"shroot: registry %s: HTTP %ld\n",kind,response.status);
        }
        free(response.challenge);
        if (r || !retry) break;
    }
    free(url); return r;
}
static int verify(int fd,const char *digest,uint64_t size,char hash[65]) {
    struct stat st;
    int r=fstat(fd,&st) ? -errno : 0;
    if (!r && (!S_ISREG(st.st_mode) || st.st_size<0 || (uint64_t)st.st_size!=size)) r=-EBADMSG;
    if (!r) r=md_image_hash(fd,size,hash);
    if (!r && digest && strcmp(digest+7,hash)) r=-EBADMSG;
    return r;
}
static int cached(struct registry *reg,const char *digest,uint64_t size,int *out) {
    *out=-1;
    int fd=openat(reg->cache,digest+7,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -errno;
    char hash[65];
    int r=verify(fd,digest,size,hash);
    if (r) close(fd); else *out=fd;
    return r;
}
static int cache_publish(struct registry *reg,struct download *download,const char *digest,uint64_t size) {
    int existing=-1;
    int r=cached(reg,digest,size,&existing);
    if (existing>=0) close(existing);
    if (r!=-ENOENT) return r;
    if (fsync(download->fd)) return -errno;
    r=(int)md_host_rename(reg->cache,download->name,reg->cache,digest+7,RENAME_NOREPLACE);
    if (r) return r;
    return fsync(reg->cache) ? -errno : 0;
}
static int fetch(struct registry *reg,const struct md_image_descriptor *d,uint64_t limit,int *out) {
    *out=-1;
    if (d->size>limit) return -EFBIG;
    int r=cached(reg,d->digest,d->size,out);
    if (r!=-ENOENT) return r;
    printf("Downloading %s (%llu bytes)\n",d->digest,(unsigned long long)d->size);
    fflush(stdout);
    struct download download;
    r=download_open(reg,&download);
    if (r) return r;
    int fd=download.fd;
    /* A small blob may first receive a larger authentication error document. */
    r=request(reg,"blobs",d->digest,fd,d->size>JSON_LIMIT ? d->size : JSON_LIMIT);
    char hash[65];
    if (!r) r=verify(fd,d->digest,d->size,hash);
    if (!r) r=cache_publish(reg,&download,d->digest,d->size);
    if (!r) {
        *out=fcntl(fd,F_DUPFD_CLOEXEC,0);
        if (*out<0) r=-errno;
    }
    download_close(reg,&download);
    return r;
}
static int manifest(struct registry *reg,char **out,struct md_image_descriptor *identity) {
    *out=NULL; memset(identity,0,sizeof(*identity));
    struct md_image_descriptor expected={0};
    char selector[140]; strcpy(selector,reg->reference.selector);
    int r=0;
    for (unsigned depth=0; !r; ++depth) {
        if (depth==5) { r=-ELOOP; break; }
        struct download download;
        r=download_open(reg,&download);
        if (r) break;
        int fd=download.fd;
        r=request(reg,"manifests",selector,fd,JSON_LIMIT);
        struct stat st;
        char hash[65],digest[72],*json=NULL,*media=NULL;
        if (!r && fstat(fd,&st)) r=-errno;
        uint64_t size=r ? 0 : (uint64_t)st.st_size;
        if (!r && expected.media && size!=expected.size) r=-EBADMSG;
        if (!r) r=verify(fd,!strncmp(selector,"sha256:",7) ? selector : NULL,size,hash);
        if (!r) snprintf(digest,sizeof(digest),"sha256:%s",hash);
        if (!r) r=md_image_read(fd,JSON_LIMIT,&json);
        if (!r) r=md_json_validate(reg->json,json,strlen(json));
        if (!r) r=md_image_schema(reg->json,json);
        if (!r) r=md_json_string(reg->json,json,"$.mediaType",&media);
        if (!r && expected.media && strcmp(expected.media,media)) r=-EBADMSG;
        int index=!r && (!strcmp(media,"application/vnd.oci.image.index.v1+json")
            || !strcmp(media,"application/vnd.docker.distribution.manifest.list.v2+json"));
        if (!r && !index && strcmp(media,"application/vnd.oci.image.manifest.v1+json")
            && strcmp(media,"application/vnd.docker.distribution.manifest.v2+json")) r=-ENOTSUP;
        if (!r) r=cache_publish(reg,&download,digest,size);
        download_close(reg,&download);
        md_image_descriptor_free(&expected);
        if (!r && index) r=md_image_index_descriptor(reg->json,json,NULL,&expected);
        if (!r && index) strcpy(selector,expected.digest);
        if (!r && !index) {
            *out=json; identity->media=media; identity->size=size; strcpy(identity->digest,digest);
            break;
        }
        free(json); free(media);
    }
    md_image_descriptor_free(&expected); return r;
}
static int save_json(int directory,const char *name,const char *text) {
    int fd=openat(directory,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return -errno;
    int r=md_image_write(fd,text,strlen(text));
    close(fd); return r;
}
int md_registry_pull(sqlite3 *json,const char *reference,int cache,int layout,
        const struct md_http_trust *trust,char digest[72]) {
    struct registry reg={.json=json,.cache=cache};
    int r=md_oci_reference_parse(reference,&reg.reference);
    if (!r) { printf("Resolving OCI image %s\n",reference); fflush(stdout); }
    /* The catalog mutation lock is held for the entire pull. */
    if (!r) r=recover_downloads(cache);
    if (!r) r=md_http_open(trust,&reg.http);
    char *document=NULL,*config=NULL;
    struct md_image_descriptor identity={0},descriptor={0};
    if (!r) r=manifest(&reg,&document,&identity);
    if (!r) r=md_image_config_descriptor(json,document,&descriptor);
    int fd=-1;
    if (!r) r=fetch(&reg,&descriptor,JSON_LIMIT,&fd);
    if (!r) r=md_image_read(fd,JSON_LIMIT,&config);
    if (!r) r=md_json_validate(json,config,strlen(config));
    if (!r) r=md_image_config_validate(json,config);
    if (fd>=0) close(fd);
    md_image_descriptor_free(&descriptor);
    sqlite3_stmt *q=NULL;
    if (!r) r=md_json_query(json,document,"SELECT json_type(?1,'$.layers'),json_array_length(?1,'$.layers')",&q);
    if (!r && (sqlite3_step(q)!=SQLITE_ROW || sqlite3_column_type(q,0)!=SQLITE_TEXT
            || strcmp((const char *)sqlite3_column_text(q,0),"array") || sqlite3_column_int64(q,1)>256)) r=-EINVAL;
    sqlite3_finalize(q); q=NULL;
    if (!r) r=md_json_query(json,document,"SELECT type,value FROM json_each(?1,'$.layers')",&q);
    uint64_t total=0;
    while (!r) {
        int step=sqlite3_step(q);
        if (step==SQLITE_DONE) break;
        if (step!=SQLITE_ROW || strcmp((const char *)sqlite3_column_text(q,0),"object")) { r=-EINVAL; break; }
        r=md_image_descriptor_read(json,(const char *)sqlite3_column_text(q,1),&descriptor);
        if (!r && descriptor.size>MD_IMAGE_MAX_BYTES-total) r=-EFBIG;
        if (!r) total+=descriptor.size;
        fd=-1;
        if (!r) r=fetch(&reg,&descriptor,MD_IMAGE_MAX_BYTES,&fd);
        if (fd>=0) close(fd);
        md_image_descriptor_free(&descriptor);
    }
    sqlite3_finalize(q); q=NULL;
    if (!r) r=md_json_query(json,document,
        "SELECT json_object('schemaVersion',2,'manifests',json_array(json_object("
        "'mediaType',json_extract(?1,'$.mediaType'),'digest',?2,'size',?3)))",&q);
    if (!r && (sqlite3_bind_text(q,2,identity.digest,-1,SQLITE_STATIC)!=SQLITE_OK
            || sqlite3_bind_int64(q,3,(sqlite3_int64)identity.size)!=SQLITE_OK)) r=-ENOMEM;
    if (!r && sqlite3_step(q)!=SQLITE_ROW) r=-EIO;
    if (!r) r=save_json(layout,"index.json",(const char *)sqlite3_column_text(q,0));
    if (!r) r=save_json(layout,"oci-layout","{\"imageLayoutVersion\":\"1.0.0\"}");
    if (!r) strcpy(digest,identity.digest);
    sqlite3_finalize(q); md_image_descriptor_free(&identity);
    free(document); free(config); free(reg.token); md_http_close(reg.http);
    return r;
}
