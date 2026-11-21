#define _GNU_SOURCE
#include "image_presentation.h"
#include "image_io.h"
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_icon(struct md_inode_store *s,const char *path,void *data,size_t limit) {
    struct stat st;
    if (md_inode_stat(s,-1,path,0,&st) || !S_ISREG(st.st_mode) || st.st_size<8 || (uint64_t)st.st_size>limit) return 0;
    int fd=md_inode_open(s,-1,path,O_RDONLY|O_CLOEXEC|O_NONBLOCK,0);
    if (fd<0) return 0;
    int size=0;
    if (!fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_size>=8 && (uint64_t)st.st_size<=limit
            && pread(fd,data,st.st_size,0)==st.st_size && !memcmp(data,"\211PNG\r\n\032\n",8)) size=(int)st.st_size;
    close(fd); return size;
}

static int read_text(struct md_inode_store *s,const char *path,size_t limit,char **out) {
    struct stat st;
    int r=md_inode_stat(s,-1,path,0,&st);
    if (r) return r;
    if (!S_ISREG(st.st_mode) || st.st_size<0 || (uint64_t)st.st_size>limit) return -EFBIG;
    int fd=md_inode_open(s,-1,path,O_RDONLY|O_CLOEXEC|O_NONBLOCK,0);
    if (fd<0) return fd;
    r=md_image_read(fd,limit,out); close(fd); return r;
}

/* Installed icon themes may declare nonstandard directory names and scaled
 * assets. Read the first hicolor index, but search its entries across roots. */
static int indexed_icon(struct md_inode_store *s,const char **roots,unsigned count,const char *name,
        const char *ext,void *data,size_t limit) {
    char path[PATH_MAX],*index=NULL;
    for (unsigned i=0;i<count && !index;++i) {
        int n=snprintf(path,sizeof(path),"%s/icons/hicolor/index.theme",roots[i]);
        if (n>0 && n<(int)sizeof(path)) read_text(s,path,128*1024,&index);
    }
    char *cursor=index,*line; int section=0,size=0; unsigned remaining=1024;
    while (cursor && remaining && !size && (line=strsep(&cursor,"\n"))) {
        line[strcspn(line,"\r")]=0;
        if (*line=='[') section=!strcmp(line,"[Icon Theme]");
        if (!section) continue;
        char *dirs=NULL;
        if (!strncmp(line,"Directories=",12)) dirs=line+12;
        if (!strncmp(line,"ScaledDirectories=",18)) dirs=line+18;
        char *dir;
        while (dirs && remaining && !size && (dir=strsep(&dirs,","))) {
            --remaining;
            if (!*dir || *dir=='/' || strstr(dir,"..") || strlen(dir)>255) continue;
            for (unsigned i=0;i<count && !size;++i) {
                int n=snprintf(path,sizeof(path),"%s/icons/hicolor/%s/%s%s",roots[i],dir,name,ext);
                if (n>0 && n<(int)sizeof(path)) size=read_icon(s,path,data,limit);
            }
        }
    }
    free(index); return size;
}

int md_image_find_icon(struct md_inode_store *s,const char **roots,unsigned count,const char *name,int branding,
        void *data,size_t limit) {
    if (!name || !*name) return 0;
    if (*name=='/' && !branding) return read_icon(s,name,data,limit);
    if (strchr(name,'/')) return 0;
    const char *ext=strlen(name)>=4 && !strcmp(name+strlen(name)-4,".png") ? "" : ".png";
    const int sizes[]={96,64,48,128,32,256,24,16};
    const int launcher[]={192,256,128,96,64,48,32,24,16};
    const char *contexts[]={"apps","places","categories","emblems"};
    char path[PATH_MAX];
    for (unsigned root=0;root<count;++root) {
        int n=snprintf(path,sizeof(path),"%s/icons/hicolor",roots[root]);
        struct stat st;
        if (n>0 && n<(int)sizeof(path) && !md_inode_stat(s,-1,path,0,&st) && S_ISDIR(st.st_mode))
            for (unsigned i=0;i<(branding ? sizeof(launcher)/sizeof(*launcher) : sizeof(sizes)/sizeof(*sizes));++i)
                for (unsigned j=0;j<(branding ? sizeof(contexts)/sizeof(*contexts) : 1);++j) {
                    int pixels=branding ? launcher[i] : sizes[i];
                    n=snprintf(path,sizeof(path),"%s/icons/hicolor/%dx%d/%s/%s%s",roots[root],pixels,pixels,contexts[j],name,ext);
                    int bytes=n>0 && n<(int)sizeof(path) ? read_icon(s,path,data,limit) : 0;
                    if (bytes) return bytes;
                }
        if (!branding) {
            n=snprintf(path,sizeof(path),"%s/pixmaps/%s%s",roots[root],name,ext);
            int size=n>0 && n<(int)sizeof(path) ? read_icon(s,path,data,limit) : 0;
            if (size) return size;
        }
    }
    if (!branding) return 0;
    int size=indexed_icon(s,roots,count,name,ext,data,limit);
    if (size) return size;
    const char *fallback[]={"icons","pixmaps"};
    for (unsigned i=0;i<count;++i) for (unsigned j=0;j<2;++j) {
        int n=snprintf(path,sizeof(path),"%s/%s/%s%s",roots[i],fallback[j],name,ext);
        int bytes=n>0 && n<(int)sizeof(path) ? read_icon(s,path,data,limit) : 0;
        if (bytes) return bytes;
    }
    return 0;
}

static char *release_value(char *v) {
    v+=strspn(v," \t"); size_t n=strlen(v);
    while (n && strchr(" \t\r",v[n-1])) v[--n]=0;
    char quote=*v=='\'' || *v=='"' ? *v++ : 0;
    char *start=v,*out=v;
    for (;*v;++v) {
        if (quote && *v==quote) { if (v[1]) return NULL; *out=0; return start; }
        if (*v=='\\' && quote!='\'' && v[1] && (!quote || strchr("\\\"`$",v[1]))) ++v;
        if ((unsigned char)*v<32) return NULL;
        *out++=*v;
    }
    *out=0; return quote ? NULL : start;
}

int md_image_os_info(const char *path) {
    struct md_inode_store *s=NULL;
    int r=md_inode_store_open_inspect(path,&s);
    if (r) return r;
    char *text=NULL,*pretty="",*version="",*logo="";
    const char *files[]={"/etc/os-release","/usr/lib/os-release"};
    for (unsigned i=0;i<2;++i) {
        if (read_text(s,files[i],16384,&text)!=-ENOENT) break;
    }
    char *cursor=text,*line;
    while (cursor && (line=strsep(&cursor,"\n"))) {
        char *eq=strchr(line,'='); if (!eq) continue;
        *eq++=0;
        char **field=!strcmp(line,"PRETTY_NAME") ? &pretty : !strcmp(line,"VERSION_ID") ? &version
            : !strcmp(line,"LOGO") ? &logo : NULL;
        if (!field) continue;
        char *v=release_value(eq);
        if (v && strlen(v)<=255) *field=v;
    }
    const char *roots[]={"/usr/local/share","/usr/share"};
    unsigned char *data=*logo ? malloc(128*1024) : NULL;
    int bytes=data ? md_image_find_icon(s,roots,2,logo,1,data,128*1024) : 0;
    sqlite3_stmt *q=NULL;
    r=mdi_prepare(s,"SELECT json_object('prettyName',?1,'versionId',?2,'png',lower(hex(?3)))",&q);
    if (!r) {
        sqlite3_bind_text(q,1,pretty,-1,SQLITE_STATIC); sqlite3_bind_text(q,2,version,-1,SQLITE_STATIC);
        sqlite3_bind_blob(q,3,data,bytes,SQLITE_STATIC);
        r=sqlite3_step(q)==SQLITE_ROW && puts((const char *)sqlite3_column_text(q,0))!=EOF ? 0 : -EIO;
    }
    sqlite3_finalize(q); free(data); free(text); md_inode_store_close(s); return r;
}
