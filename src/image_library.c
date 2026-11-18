#define _GNU_SOURCE
#include "host_open.h"
#include "image_library.h"
#include "image_io.h"
#include "image_json.h"
#include "image_import.h"
#include "image_registry.h"
#include "image_publish.h"
#include "image_backup.h"
#include "image_maintenance.h"
#include "image_prepare.h"
#include "image_launch.h"
#include "inode_store.h"
#include "storage_paths.h"
#include "private_tree.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int valid_name(const char *name) {
    return name && *name && strlen(name) <= 64
        && strspn(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") == strlen(name)
        && strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", *name);
}
static int uuid_valid(const char *id) {
    if (!id || strlen(id) != 36) return 0;
    for (int i=0; i<36; ++i) {
        if (i==8 || i==13 || i==18 || i==23) { if (id[i]!='-') return 0; }
        else if (!strchr("0123456789abcdef", id[i])) return 0;
    }
    return 1;
}
static int uuid(char out[37]) {
    unsigned char data[16];
    for (size_t n=0; n<sizeof(data);) {
        ssize_t size=getrandom(data+n, sizeof(data)-n, 0);
        if (size<0 && errno==EINTR) continue;
        if (size<=0) return size<0 ? -errno : -EIO;
        n+=(size_t)size;
    }
    data[6]=(data[6]&15)|64; data[8]=(data[8]&63)|128;
    size_t at=0;
    for (size_t i=0; i<sizeof(data); ++i) {
        if (i==4 || i==6 || i==8 || i==10) out[at++]='-';
        out[at++]="0123456789abcdef"[data[i]>>4]; out[at++]="0123456789abcdef"[data[i]&15];
    }
    out[at]=0; return 0;
}
int md_library_path(const struct md_library *lib, const char *group, const char *name, char out[PATH_MAX]) {
    int n=snprintf(out, PATH_MAX, "%s/%s%s%s", lib->path, group, name ? "/" : "", name ? name : "");
    return n<0 || n>=PATH_MAX ? -ENAMETOOLONG : 0;
}
int md_library_lock(int root) {
    int fd=openat(root, "library.lock", O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (fd<0) return -errno;
    struct stat st;
    int r=fstat(fd,&st) ? -errno : !S_ISREG(st.st_mode) ? -EINVAL : 0;
    /* POSIX lock interoperates with existing catalog writers and relocation. */
    struct flock lock={.l_type=F_WRLCK, .l_whence=SEEK_SET};
    if (!r && fcntl(fd,F_SETLK,&lock)) r=errno==EAGAIN || errno==EACCES ? -EBUSY : -errno;
    if (r) { close(fd); return r; }
    return fd;
}
static void close_library(struct md_library *lib) {
    if (lib->json) sqlite3_close(lib->json);
    if (lib->names>=0) close(lib->names);
    if (lib->lock>=0) close(lib->lock);
    if (lib->root>=0) close(lib->root);
}
static int open_library(const char *path, int create, int locked, struct md_library *lib) {
    *lib=(struct md_library){.root=-1, .names=-1, .lock=-1};
    if (create && mkdir(path,0700) && errno!=EEXIST) return -errno;
    lib->root=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (lib->root<0) return -errno;
    int r=md_storage_directory_path(lib->root,lib->path,sizeof(lib->path));
    if (!r && locked && (lib->lock=md_library_lock(lib->root))<0) r=lib->lock;
    const char *groups[]={"names","instances","images","layers","cache","work"};
    for (size_t i=0; !r && i<sizeof(groups)/sizeof(*groups); ++i) {
        if (create && mkdirat(lib->root,groups[i],0700) && errno!=EEXIST) { r=-errno; break; }
        int fd=openat(lib->root,groups[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (fd<0) r=-errno;
        else if (!i) lib->names=fd;
        else close(fd);
    }
    if (!r && create && fsync(lib->root)) r=-errno;
    if (!r && sqlite3_open(":memory:",&lib->json)!=SQLITE_OK) r=-ENOMEM;
    return r;
}
int md_library_each(int directory, int (*visit)(int,const char *,void *), void *data) {
    int scan=openat(directory,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (scan<0) return -errno;
    DIR *dir=fdopendir(scan);
    if (!dir) { int r=-errno; close(scan); return r; }
    int r=0;
    while (!r) {
        errno=0;
        struct dirent *entry=readdir(dir);
        if (!entry) { if (errno) r=-errno; break; }
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        r=visit(directory,entry->d_name,data);
    }
    closedir(dir); return r;
}
int md_library_read(struct md_library *lib, const char *name, struct md_environment *out) {
    memset(out,0,sizeof(*out));
    if (!valid_name(name)) return -EINVAL;
    char file[70]; snprintf(file,sizeof(file),"%s.json",name);
    int fd=openat(lib->names,file,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if (fd<0) return -errno;
    char *text=NULL;
    int r=md_image_read(fd,8*1024*1024,&text);
    close(fd);
    if (!r) r=md_json_validate(lib->json,text,strlen(text));
    sqlite3_stmt *q=NULL;
    if (!r) r=md_json_query(lib->json,text,
        "SELECT json_type(?1,'$.format'), json_extract(?1,'$.format')",&q);
    int version=0;
    if (!r) {
        if (sqlite3_step(q)!=SQLITE_ROW || sqlite3_column_type(q,0)!=SQLITE_TEXT
                || strcmp((const char *)sqlite3_column_text(q,0),"integer")) r=-EINVAL;
        else {
            sqlite3_int64 value=sqlite3_column_int64(q,1);
            if (value!=1 && value!=2) r=-EPROTONOSUPPORT;
            else version=(int)value;
        }
    }
    sqlite3_finalize(q);
    char *values[5]={0};
    const char *fields[]={"$.name","$.id","$.image","$.source",version==1 ? "$.id" : "$.store"};
    for (size_t i=0; !r && i<5; ++i) r=md_json_string(lib->json,text,fields[i],&values[i]);
    if (!r && (strcmp(values[0],name) || !uuid_valid(values[1]) || !uuid_valid(values[4])
            || strlen(values[2])>128 || (*values[2] && (!strchr("abcdefghijklmnopqrstuvwxyz0123456789",values[2][0])
                || strspn(values[2],"abcdefghijklmnopqrstuvwxyz0123456789-")!=strlen(values[2]))))) r=-EINVAL;
    if (!r) {
        strcpy(out->name,name); strcpy(out->id,values[1]); strcpy(out->key,values[4]); strcpy(out->image,values[2]);
        out->source=values[3]; values[3]=NULL;
    }
    for (size_t i=0; i<5; ++i) free(values[i]);
    free(text); return r;
}
struct record_visit { struct md_library *lib; int (*visit)(struct md_library *,const struct md_environment *,void *); void *data; };
static int visit_record(int directory, const char *name, void *opaque) {
    (void)directory;
    struct record_visit *visit=opaque;
    if (!strncmp(name,".publish-",9)) return 0;
    size_t n=strlen(name);
    if (n<=5 || n>69 || strcmp(name+n-5,".json")) return -EINVAL;
    char key[65]; memcpy(key,name,n-5); key[n-5]=0;
    struct md_environment item;
    int r=md_library_read(visit->lib,key,&item);
    if (!r) r=visit->visit(visit->lib,&item,visit->data);
    free(item.source); return r;
}
int md_library_records(struct md_library *lib, int (*visit)(struct md_library *,const struct md_environment *,void *), void *data) {
    struct record_visit state={lib,visit,data};
    return md_library_each(lib->names,visit_record,&state);
}
static int record_json(struct md_library *lib, const struct md_environment *item, int stored, char **out) {
    *out=NULL;
    char path[PATH_MAX];
    int r=md_library_path(lib,"instances",item->key,path);
    sqlite3_stmt *q=NULL;
    const char *sql=stored ? "SELECT json_object('format',2,'name',?1,'id',?2,'store',?3,'image',?4,'source',?5)"
        : "SELECT json_object('name',?1,'id',?2,'store',?3,'image',?4,'source',?5)";
    if (!r && sqlite3_prepare_v2(lib->json,sql,-1,&q,NULL)!=SQLITE_OK) r=-ENOMEM;
    const char *values[]={item->name,item->id,stored ? item->key : path,item->image,item->source};
    for (int i=0; !r && i<5; ++i) if (sqlite3_bind_text(q,i+1,values[i],-1,SQLITE_STATIC)!=SQLITE_OK) r=-ENOMEM;
    if (!r && sqlite3_step(q)!=SQLITE_ROW) r=-EIO;
    if (!r && !(*out=strdup((const char *)sqlite3_column_text(q,0)))) r=-ENOMEM;
    sqlite3_finalize(q); return r;
}
static int output_record(struct md_library *lib, const struct md_environment *item) {
    char *json=NULL;
    int r=record_json(lib,item,0,&json);
    if (!r && puts(json)==EOF) r=-EIO;
    free(json); return r;
}
static int collect_record(struct md_library *lib, const struct md_environment *item, void *opaque) {
    (void)opaque;
    char *json=NULL;
    int r=record_json(lib,item,0,&json);
    sqlite3_stmt *q=NULL;
    if (!r) r=md_json_query(lib->json,json,"INSERT INTO records VALUES(json_extract(?1,'$.name'),?1)",&q);
    if (!r && sqlite3_step(q)!=SQLITE_DONE) r=-EIO;
    sqlite3_finalize(q); free(json); return r;
}
static int list(struct md_library *lib) {
    int r=sqlite3_exec(lib->json,"CREATE TABLE records(name TEXT PRIMARY KEY,record TEXT)",NULL,NULL,NULL)==SQLITE_OK ? 0 : -ENOMEM;
    if (!r) r=md_library_records(lib,collect_record,NULL);
    sqlite3_stmt *q=NULL;
    if (!r && sqlite3_prepare_v2(lib->json,
            "SELECT json_group_array(json(record)) FROM (SELECT record FROM records ORDER BY name)",-1,&q,NULL)!=SQLITE_OK) r=-ENOMEM;
    if (!r && sqlite3_step(q)!=SQLITE_ROW) r=-EIO;
    if (!r && puts((const char *)sqlite3_column_text(q,0))==EOF) r=-EIO;
    sqlite3_finalize(q); return r;
}
static int require_new(struct md_library *lib,const char *name) {
    if (!valid_name(name)) return -EINVAL;
    char file[70]; snprintf(file,sizeof(file),"%s.json",name);
    struct stat st;
    return !fstatat(lib->names,file,&st,AT_SYMLINK_NOFOLLOW) ? -EEXIST : errno==ENOENT ? 0 : -errno;
}
static int publish(struct md_library *lib,const struct md_environment *item) {
    char id[37]={0},stage[50],name[70],*json=NULL;
    int r=uuid(id);
    snprintf(stage,sizeof(stage),".publish-%s",id);
    snprintf(name,sizeof(name),"%s.json",item->name);
    if (!r) r=record_json(lib,item,1,&json);
    int fd=-1;
    if (!r && (fd=openat(lib->names,stage,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600))<0) r=-errno;
    if (!r) r=md_image_write(fd,json,strlen(json));
    if (!r && fsync(fd)) r=-errno;
    if (fd>=0) close(fd);
    if (!r) r=(int)md_host_rename(lib->names,stage,lib->names,name,RENAME_NOREPLACE);
    /* After rename, a sync failure is an uncertain outcome, never rollback. */
    if (!r && fsync(lib->names)) r=-errno;
    if (fd>=0) unlinkat(lib->names,stage,0);
    free(json); return r;
}
static int prepare_base(const char *path) {
    struct md_inode_store *store=NULL;
    int r=md_inode_store_open(path,0,&store);
    if (!r && !md_inode_store_readonly(store)) r=-EINVAL;
    md_inode_store_close(store); return r;
}
static int install(struct md_library *lib, const char *kind, const char *source, const char *name,
        const char *resolver,const struct md_http_trust *trust) {
    int r=require_new(lib,name);
    struct md_environment item={0};
    if (!r) { strcpy(item.name,name); item.source=(char *)source; r=uuid(item.id); }
    if (!r) r=uuid(item.key);
    char store[PATH_MAX],base[PATH_MAX],layers[PATH_MAX],input[PATH_MAX];
    if (!r) r=md_library_path(lib,"instances",item.key,store);
    int work=-1,snapshot=-1,cache=-1,layout=-1;
    char cache_path[PATH_MAX];
    struct md_image_publish staging={.stage=-1,.parent=-1};
    if (!r && !strcmp(kind,"rootfs")) {
        work=openat(lib->root,"work",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (work<0) r=-errno;
        int fd=r ? -1 : open(source,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        if (!r && fd<0) r=-errno;
        if (!r) r=md_image_snapshot(fd,work,MD_IMAGE_MAX_BYTES,&snapshot);
        if (fd>=0) close(fd);
        struct stat st;
        if (!r && fstat(snapshot,&st)) r=-errno;
        char digest[65];
        if (!r) r=md_image_hash(snapshot,(uint64_t)st.st_size,digest);
        if (!r) {
            snprintf(item.image,sizeof(item.image),"import-v%d-rootfs-%s",MD_IMAGE_IMPORT_VERSION,digest);
        }
    } else if (!r && !strcmp(kind,"oci")) {
        char id[37]; r=uuid(id);
        if (!r) snprintf(item.image,sizeof(item.image),"import-v%d-local-%s",MD_IMAGE_IMPORT_VERSION,id);
        struct stat st;
        if (!r && lstat(source,&st)) r=-errno;
        if (!r && !S_ISDIR(st.st_mode)) r=-ENOTDIR;
        if (!r && !realpath(source,input)) r=-errno;
    } else if (!r && !strcmp(kind,"registry")) {
        r=md_library_path(lib,"work","registry",input);
        if (!r) r=md_image_publish_begin(input,&staging);
        if (!r && mkdirat(staging.stage,"store",0700)) r=-errno;
        if (!r && (layout=openat(staging.stage,"store",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC))<0) r=-errno;
        if (!r && (cache=openat(lib->root,"cache",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC))<0) r=-errno;
        char digest[72];
        if (!r) r=md_registry_pull(lib->json,source,cache,layout,trust,digest);
        if (!r) {
            strcpy(input,staging.path);
            snprintf(item.image,sizeof(item.image),"import-v%d-oci-%s",MD_IMAGE_IMPORT_VERSION,digest+7);
            r=md_library_path(lib,"cache",NULL,cache_path);
        }
    }
    if (!r && strcmp(kind,"restore")) {
        r=md_library_path(lib,"images",item.image,base);
        struct stat st;
        if (!r && !lstat(base,&st)) r=S_ISDIR(st.st_mode) ? prepare_base(base) : -EINVAL;
        else if (!r && errno!=ENOENT) r=-errno;
        else if (!r && !strcmp(kind,"rootfs")) r=md_image_archive_snapshot(snapshot,base,0);
        else if (!r) {
            r=md_library_path(lib,"layers",NULL,layers);
            if (!r) r=md_image_import(input,base,NULL,1,layers,cache>=0 ? cache_path : NULL);
        }
        if (!r) r=md_image_create(base,store);
    } else if (!r) r=md_image_archive_import(source,store,1);
    if (snapshot>=0) close(snapshot);
    if (work>=0) close(work);
    if (cache>=0) close(cache);
    if (layout>=0) close(layout);
    md_image_publish_close(&staging);
    if (!r && resolver) r=md_image_resolver(store,resolver,0);
    if (!r) r=publish(lib,&item);
    if (!r) r=output_record(lib,&item);
    /* Failed unpublished instances are collected by the dependency-aware prune. */
    return r;
}
static int remove_environment(struct md_library *lib,const struct md_environment *item) {
    int r=md_library_check_remove(lib,item);
    char store[PATH_MAX];
    if (!r) r=md_library_path(lib,"instances",item->key,store);
    if (!r) { r=md_image_remove(store,0); if (r==-ENOENT) r=0; }
    char file[70]; snprintf(file,sizeof(file),"%s.json",item->name);
    if (!r && unlinkat(lib->names,file,0)) r=-errno;
    if (!r && fsync(lib->names)) r=-errno;
    return r;
}
int md_library_command(int argc,char **argv) {
    if (argc<2 || !*argv[0]) return -EINVAL;
    const char *operation=argv[1];
    int install_command=!strcmp(operation,"install"),restore=!strcmp(operation,"restore");
    int r=0;
    const char *resolver=NULL;
    struct md_http_trust trust={0};
    if (install_command) {
        if (argc<5 || (strcmp(argv[2],"rootfs") && strcmp(argv[2],"oci") && strcmp(argv[2],"registry"))) return -EINVAL;
        for (int i=5; i<argc; i+=2) {
            const char **field=!strcmp(argv[i],"--resolver") ? &resolver
                : !strcmp(argv[i],"--ca-file") ? &trust.file
                : !strcmp(argv[i],"--ca-directory") ? &trust.directory : NULL;
            if (!field || *field || i+1>=argc) return -EINVAL;
            *field=argv[i+1];
        }
        if (strcmp(argv[2],"registry") && (trust.file || trust.directory)) return -EINVAL;
    }
    if (restore && argc!=4) return -EINVAL;
    if (!strcmp(operation,"init") && argc!=2) return -EINVAL;
    struct md_library lib;
    int locked=strcmp(operation,"list") && strcmp(operation,"resolve");
    r=open_library(argv[0],install_command || restore || !strcmp(operation,"init"),locked,&lib);
    if (r) fprintf(stderr,"shroot: library %s: %s\n",argv[0],strerror(-r));
    if (!r && argc==2 && !strcmp(operation,"init")) { }
    else if (!r && install_command) r=install(&lib,argv[2],argv[3],argv[4],resolver,&trust);
    else if (!r && restore) r=install(&lib,"restore",argv[2],argv[3],NULL,NULL);
    else if (!r && argc==2 && !strcmp(operation,"list")) r=list(&lib);
    else if (!r && argc==2 && !strcmp(operation,"prune")) r=md_library_prune(&lib);
    else if (!r && argc>=3) {
        struct md_environment item;
        r=md_library_read(&lib,argv[2],&item);
        char store[PATH_MAX];
        if (!r) r=md_library_path(&lib,"instances",item.key,store);
        if (!r && argc==3 && !strcmp(operation,"resolve")) {
            int fd=open(store,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if (fd<0) r=-errno;
            else { close(fd); r=output_record(&lib,&item); }
        }
        else if (!r && argc==3 && !strcmp(operation,"remove")) r=remove_environment(&lib,&item);
        else if (!r && argc==4 && !strcmp(operation,"backup")) r=md_image_backup(store,argv[3]);
        else if (!r && (argc==4 || (argc==5 && !strcmp(argv[4],"--replace"))) && !strcmp(operation,"resolver"))
            r=md_image_resolver(store,argv[3],argc==5);
        else if (!r && (!strcmp(operation,"run") || !strcmp(operation,"exec") || !strcmp(operation,"login"))) {
            /* Resolve once under the catalog lock; native runtime admission
             * owns subsequent store lifetime, without a second name lookup. */
            argv[2]=store;
            r=md_image_launch(!strcmp(operation,"run") ? MD_IMAGE_RUN : !strcmp(operation,"exec") ? MD_IMAGE_EXEC : MD_IMAGE_LOGIN,argc-2,argv+2);
        } else if (!r) r=-EINVAL;
        free(item.source);
    } else if (!r) r=-EINVAL;
    close_library(&lib); return r;
}
