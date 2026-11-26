#define _GNU_SOURCE
#include "image_oci_archive.h"
#include "image_backup.h"
#include "image_io.h"
#include "image_oci.h"
#include "image_json.h"
#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OCI "application/vnd.oci.image."
#define BLOBS "blobs/sha256/"
#define DIGEST_PATH(key) "$.annotations.\"" key "\""

int md_oci_snapshot_policy(sqlite3 *db,const char *manifest,size_t layers,int *snapshot,int *guest_users) {
    sqlite3_stmt *q=NULL;
    int r=md_json_query(db,manifest,"SELECT json_type(?1,'" DIGEST_PATH(SHROOT_SNAPSHOT) "'),"
        "json_extract(?1,'" DIGEST_PATH(SHROOT_SNAPSHOT) "'),json_type(?1,'" DIGEST_PATH(SHROOT_GUEST_USERS) "'),"
        "json_extract(?1,'" DIGEST_PATH(SHROOT_GUEST_USERS) "')",&q);
    *snapshot=0;
    if (!r && sqlite3_step(q)!=SQLITE_ROW) r=-EINVAL;
    if (!r && (sqlite3_column_type(q,0)!=SQLITE_NULL || sqlite3_column_type(q,2)!=SQLITE_NULL)) {
        if (sqlite3_column_type(q,1)!=SQLITE_TEXT || sqlite3_column_type(q,3)!=SQLITE_TEXT || layers!=1) r=-EINVAL;
        else if (strcmp((const char *)sqlite3_column_text(q,1),"1")) r=-EPROTONOSUPPORT;
        else {
            const char *users=(const char *)sqlite3_column_text(q,3);
            if (strcmp(users,"0") && strcmp(users,"1")) r=-EINVAL;
            else { *snapshot=1; *guest_users=*users=='1'; }
        }
    }
    sqlite3_finalize(q); return r;
}

static int member(struct archive *ar,const char *name,const char *body,int fd,uint64_t size) {
    struct archive_entry *entry=archive_entry_new();
    if (!entry) return -ENOMEM;
    archive_entry_set_pathname(entry,name); archive_entry_set_mode(entry,S_IFREG|0644);
    archive_entry_set_size(entry,(int64_t)size);
    int r=archive_write_header(ar,entry)==ARCHIVE_OK ? 0 : -EIO;
    archive_entry_free(entry);
    if (!r && body) return archive_write_data(ar,body,size)==(la_ssize_t)size ? 0 : -EIO;
    char buffer[65536];
    for (uint64_t offset=0; !r && offset<size;) {
        size_t take=size-offset>sizeof(buffer) ? sizeof(buffer) : (size_t)(size-offset);
        ssize_t n=pread(fd,buffer,take,offset);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) r=n<0 ? -errno : -EIO;
        else if (archive_write_data(ar,buffer,n)!=n) r=-EIO;
        else offset+=n;
    }
    return r;
}

static int blob(struct archive *ar,const char *media,const char *body,int fd,uint64_t size,
        const char *hash,char descriptor[256]) {
    char path[sizeof(BLOBS)+64];
    snprintf(path,sizeof(path),BLOBS "%s",hash);
    snprintf(descriptor,256,"{\"mediaType\":\"" OCI "%s\",\"digest\":\"sha256:%s\",\"size\":%llu}",
        media,hash,(unsigned long long)size);
    return member(ar,path,body,fd,size);
}
static int json_blob(struct archive *ar,const char *media,const char *body,char hash[65],char descriptor[256]) {
    size_t size=strlen(body);
    int r=md_image_hash_bytes(body,size,hash);
    return r ? r : blob(ar,media,body,-1,size,hash,descriptor);
}
int md_oci_archive_write(int out,int layer,sqlite3 *db,const char *config,int guest_users) {
    struct stat st;
    if (fstat(layer,&st)) return -errno;
    if (st.st_size<0 || (uint64_t)st.st_size>MD_IMAGE_MAX_BYTES) return -EFBIG;
    char hash[65],config_hash[65],manifest_hash[65],ld[256],cd[256],md[256];
    int r=md_image_hash(layer,st.st_size,hash);
    sqlite3_stmt *q=NULL;
    if (!r) r=md_json_query(db,config,"SELECT json_set(json_insert(json_remove(?1,'$.history'),"
        "'$.os','linux','$.architecture','arm64'),'$.rootfs',"
        "json_object('type','layers','diff_ids',json_array('sha256:'||?2)))",&q);
    if (!r && sqlite3_bind_text(q,2,hash,-1,SQLITE_STATIC)!=SQLITE_OK) r=-ENOMEM;
    if (!r && sqlite3_step(q)!=SQLITE_ROW) r=-EINVAL;
    const char *portable=NULL;
    if (!r && sqlite3_column_bytes(q,0)>8*1024*1024) r=-EFBIG;
    if (!r) {
        portable=(const char *)sqlite3_column_text(q,0);
        r=portable ? md_image_config_validate(db,portable) : -ENOMEM;
    }
    struct archive *ar=archive_write_new();
    if (!ar && !r) r=-ENOMEM;
    if (!r && (archive_write_set_format_pax_restricted(ar)!=ARCHIVE_OK ||
            archive_write_add_filter_zstd(ar)!=ARCHIVE_OK || archive_write_open_fd(ar,out)!=ARCHIVE_OK)) r=-EIO;
    const char layout[]="{\"imageLayoutVersion\":\"1.0.0\"}";
    if (!r) r=member(ar,"oci-layout",layout,-1,sizeof(layout)-1);
    if (!r) r=blob(ar,"layer.v1.tar",NULL,layer,st.st_size,hash,ld);
    uint64_t content_size=st.st_size+sizeof(layout)-1;
    if (!r) {
        content_size+=strlen(portable);
        r=json_blob(ar,"config.v1+json",portable,config_hash,cd);
    }
    sqlite3_finalize(q);
    char manifest[1024],index[512];
    if (!r) {
        snprintf(manifest,sizeof(manifest),"{\"schemaVersion\":2,\"mediaType\":\"" OCI "manifest.v1+json\","
            "\"config\":%s,\"layers\":[%s],\"annotations\":{\"" SHROOT_SNAPSHOT "\":\"1\",\""
            SHROOT_GUEST_USERS "\":\"%d\"}}",cd,ld,guest_users);
        content_size+=strlen(manifest);
        r=json_blob(ar,"manifest.v1+json",manifest,manifest_hash,md);
    }
    if (!r) {
        snprintf(index,sizeof(index),"{\"schemaVersion\":2,\"mediaType\":\"" OCI "index.v1+json\",\"manifests\":[%s]}",md);
        content_size+=strlen(index);
        r=member(ar,"index.json",index,-1,strlen(index));
    }
    if (!r) {
        /* Docker's classic image store reads this path index, not index.json. */
        char docker[256];
        snprintf(docker,sizeof(docker),"[{\"Config\":\"" BLOBS "%s\",\"RepoTags\":[],\"Layers\":[\"" BLOBS "%s\"]}]",
            config_hash,hash);
        content_size+=strlen(docker);
        r=member(ar,"manifest.json",docker,-1,strlen(docker));
    }
    if (!r && content_size>MD_IMAGE_MAX_BYTES) r=-EFBIG;
    if (ar) { if (archive_write_close(ar)!=ARCHIVE_OK && !r) r=-EIO; archive_write_free(ar); }
    if (!r && fstat(out,&st)) r=-errno;
    if (!r && (uint64_t)st.st_size>MD_IMAGE_MAX_BYTES) r=-EFBIG;
    return r;
}

/* Only OCI control files and SHA-256 blob basenames ever become host paths.
 * The ordinary layout reader owns descriptor validation and layer selection. */
int md_oci_archive_open(int fd,int scratch,int *blobs) {
    *blobs=-1;
    if (mkdirat(scratch,"oci-blobs",0700)) return -errno;
    int directory=openat(scratch,"oci-blobs",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (directory<0) return -errno;
    struct archive *ar=archive_read_new();
    int r=ar ? 0 : -ENOMEM;
    if (!r) {
        archive_read_support_format_tar(ar); archive_read_support_filter_gzip(ar); archive_read_support_filter_zstd(ar);
        if (lseek(fd,0,SEEK_SET)<0) r=-errno;
        else if (archive_read_open_fd(ar,fd,65536)!=ARCHIVE_OK) r=-EBADMSG;
    }
    uint64_t total=0,count=0;
    while (!r) {
        struct archive_entry *entry;
        int rc=archive_read_next_header(ar,&entry);
        if (rc==ARCHIVE_EOF) break;
        if (rc!=ARCHIVE_OK) { r=-EBADMSG; break; }
        if (++count>MD_IMAGE_MAX_ENTRIES) { r=-EFBIG; break; }
        const char *name=archive_entry_pathname(entry);
        while (name && !strncmp(name,"./",2)) name+=2;
        if (!name || *name=='/' || !strncmp(name,"../",3) || strstr(name,"/../") ||
                archive_entry_hardlink(entry) || archive_entry_symlink(entry) || archive_entry_is_encrypted(entry)) { r=-EINVAL; break; }
        if (archive_entry_filetype(entry)==S_IFDIR) continue;
        int64_t size=archive_entry_size(entry);
        if (archive_entry_filetype(entry)!=S_IFREG || size<0) { r=-EINVAL; break; }
        if ((uint64_t)size>MD_IMAGE_MAX_BYTES-total) { r=-EFBIG; break; }
        total+=size;
        int parent=scratch;
        if (!strcmp(name,"oci-layout") || !strcmp(name,"index.json")) {
            if (size>8*1024*1024) { r=-EFBIG; break; }
        } else if (!strncmp(name,BLOBS,sizeof(BLOBS)-1)) {
            name+=sizeof(BLOBS)-1;
            if (strlen(name)!=64 || strspn(name,"0123456789abcdef")!=64) { r=-EINVAL; break; }
            parent=directory;
        } else continue;
        int out=openat(parent,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if (out<0) { r=-errno; break; }
        char buffer[65536];
        for (int64_t pos=0; !r && pos<size;) {
            la_ssize_t n=archive_read_data(ar,buffer,sizeof(buffer));
            if (n<=0 || n>size-pos) r=-EBADMSG;
            else { r=md_image_write(out,buffer,n); pos+=n; }
        }
        if (close(out) && !r) r=-errno;
    }
    if (ar) { if (archive_read_close(ar)!=ARCHIVE_OK && !r) r=-EBADMSG; archive_read_free(ar); }
    if (r) close(directory); else *blobs=directory;
    return r;
}
