#define _GNU_SOURCE
#include "image_library.h"
#include "image_maintenance.h"
#include "image_publish.h"
#include "private_tree.h"
#include "storage_paths.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct graph { struct md_library *lib; const char *group, *excluded; int layer; };
static int sql(sqlite3 *db,const char *text) {
    int r=sqlite3_exec(db,text,NULL,NULL,NULL);
    return r==SQLITE_OK ? 0 : r==SQLITE_NOMEM ? -ENOMEM : -EIO;
}
static int query(sqlite3 *db,const char *text,const char *first,const char *second,sqlite3_stmt **out) {
    *out=NULL;
    int r=sqlite3_prepare_v2(db,text,-1,out,NULL)==SQLITE_OK ? 0 : -ENOMEM;
    if (!r && first && sqlite3_bind_text(*out,1,first,-1,SQLITE_STATIC)!=SQLITE_OK) r=-ENOMEM;
    if (!r && second && sqlite3_bind_text(*out,2,second,-1,SQLITE_STATIC)!=SQLITE_OK) r=-ENOMEM;
    return r;
}
static int update(sqlite3 *db,const char *text,const char *first,const char *second) {
    sqlite3_stmt *q=NULL;
    int r=query(db,text,first,second,&q);
    if (!r && sqlite3_step(q)!=SQLITE_DONE) r=-EIO;
    sqlite3_finalize(q); return r;
}
static int exists(sqlite3 *db,const char *text,const char *path) {
    sqlite3_stmt *q=NULL;
    int r=query(db,text,path,NULL,&q);
    if (!r) {
        int step=sqlite3_step(q);
        r=step==SQLITE_ROW ? 1 : step==SQLITE_DONE ? 0 : -EIO;
    }
    sqlite3_finalize(q); return r;
}
static int is_stage(const char *name) {
    return strlen(name)==42 && !strncmp(name,".md-image-",10) && strspn(name+10,"0123456789abcdef")==32;
}
static int directory(struct md_library *lib,const char *group,int (*visit)(int,const char *,void *),void *opaque) {
    int fd=openat(lib->root,group,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -errno;
    int r=md_library_each(fd,visit,opaque);
    close(fd); return r;
}
static int add_resource(int parent,const char *name,void *opaque) {
    struct graph *g=opaque;
    if (is_stage(name)) return 0;
    char path[PATH_MAX];
    const char *original=!strncmp(name,".md-remove-",11) ? name+11 : name;
    int r=md_library_path(g->lib,g->group,original,path);
    if (!r && g->excluded && !strcmp(g->excluded,path)) return 0;
    if (!r) r=md_library_path(g->lib,g->group,name,path);
    struct stat st;
    if (!r && fstatat(parent,name,&st,AT_SYMLINK_NOFOLLOW)) r=-errno;
    if (!r && !S_ISDIR(st.st_mode)) r=-EINVAL;
    if (!r) r=update(g->lib->json,"INSERT INTO resource(path) VALUES(?1)",path,NULL);
    return r;
}
struct edge { sqlite3 *db; const char *owner; };
static int add_edge(const char *source,void *opaque) {
    struct edge *edge=opaque;
    char path[PATH_MAX];
    /* Sources may outlive their bodies after interrupted deletion. Resolve the
     * recorded path lexically, without requiring its target to be readable. */
    int r=md_storage_source_path(edge->owner,source,path,sizeof(path));
    char *last=r ? NULL : strrchr(path,'/');
    if (!r && (!last || last==path || !last[1])) r=-EINVAL;
    if (!r) {
        *last=0;
        if (strcmp(path,edge->owner)) r=update(edge->db,"INSERT OR IGNORE INTO dependency VALUES(?1,?2)",edge->owner,path);
    }
    return r;
}
static int graph(struct md_library *lib,const char *excluded) {
    int r=sql(lib->json,
        "CREATE TABLE resource(path TEXT PRIMARY KEY,retained INTEGER NOT NULL DEFAULT 0,indegree INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX resource_ready ON resource(retained,indegree,path);"
        "CREATE TABLE dependency(owner TEXT,source TEXT,PRIMARY KEY(owner,source));"
        "CREATE INDEX dependency_source ON dependency(source,owner);");
    struct graph g={.lib=lib,.group="instances",.excluded=excluded};
    if (!r) r=directory(lib,g.group,add_resource,&g);
    g.group="images";
    if (!r) r=directory(lib,g.group,add_resource,&g);
    sqlite3_stmt *q=NULL;
    if (!r) r=query(lib->json,"SELECT path FROM resource",NULL,NULL,&q);
    int step=SQLITE_DONE;
    while (!r && (step=sqlite3_step(q))==SQLITE_ROW) {
        struct edge edge={lib->json,(const char *)sqlite3_column_text(q,0)};
        r=md_image_source_visit(edge.owner,add_edge,&edge);
    }
    if (!r && step!=SQLITE_DONE) r=-EIO;
    sqlite3_finalize(q); return r;
}
static int check_alias(struct md_library *lib,const struct md_environment *item,void *opaque) {
    (void)lib;
    const struct md_environment *target=opaque;
    return strcmp(item->name,target->name) && !strcmp(item->key,target->key) ? -EBUSY : 0;
}
int md_library_check_remove(struct md_library *lib,const struct md_environment *item) {
    int r=md_library_records(lib,check_alias,(void *)item);
    char path[PATH_MAX];
    if (!r) r=md_library_path(lib,"instances",item->key,path);
    if (!r) r=graph(lib,path);
    if (!r) {
        r=exists(lib->json,"SELECT 1 FROM dependency WHERE source=?1 LIMIT 1",path);
        if (r>0) r=-EBUSY;
    }
    return r;
}
static int retain_record(struct md_library *lib,const struct md_environment *item,void *opaque) {
    (void)opaque;
    char path[PATH_MAX];
    int r=md_library_path(lib,"instances",item->key,path);
    if (!r) r=update(lib->json,"UPDATE resource SET retained=1 WHERE path=?1",path,NULL);
    if (!r && *item->image) {
        r=md_library_path(lib,"images",item->image,path);
        if (!r) r=update(lib->json,"UPDATE resource SET retained=1 WHERE path=?1",path,NULL);
    }
    return r;
}
static int plan(struct md_library *lib) {
    int r=md_library_records(lib,retain_record,NULL);
    if (!r) r=sql(lib->json,
        "WITH RECURSIVE kept(path) AS (SELECT path FROM resource WHERE retained=1 UNION "
        "SELECT source FROM dependency JOIN kept ON owner=kept.path) "
        "UPDATE resource SET retained=1 WHERE path IN kept;"
        "UPDATE resource SET indegree=(SELECT count(*) FROM dependency JOIN resource owner ON owner.path=dependency.owner "
        "WHERE source=resource.path AND owner.retained=0) WHERE retained=0;"
        "CREATE TABLE removal(sequence INTEGER PRIMARY KEY,path TEXT);");
    while (!r) {
        sqlite3_stmt *q=NULL;
        r=query(lib->json,"SELECT path FROM resource WHERE retained=0 AND indegree=0 LIMIT 1",NULL,NULL,&q);
        int step=r ? SQLITE_ERROR : sqlite3_step(q);
        char *path=NULL;
        if (!r && step==SQLITE_ROW) { path=strdup((const char *)sqlite3_column_text(q,0)); if (!path) r=-ENOMEM; }
        else if (!r && step!=SQLITE_DONE) r=-EIO;
        sqlite3_finalize(q);
        if (!r && !path) break;
        if (!r) r=update(lib->json,"INSERT INTO removal(path) VALUES(?1)",path,NULL);
        if (!r) r=update(lib->json,"UPDATE resource SET retained=2 WHERE path=?1",path,NULL);
        if (!r) r=update(lib->json,"UPDATE resource SET indegree=indegree-1 WHERE retained=0 "
            "AND path IN (SELECT source FROM dependency WHERE owner=?1)",path,NULL);
        free(path);
    }
    if (!r) { r=exists(lib->json,"SELECT 1 FROM resource WHERE retained=0 LIMIT 1",NULL); if (r>0) r=-ELOOP; }
    return r;
}
static int finish_removal(int parent,const char *name,void *opaque) {
    struct graph *g=opaque;
    if (strncmp(name,".md-remove-",11)) return 0;
    struct stat st;
    if (!fstatat(parent,name+11,&st,AT_SYMLINK_NOFOLLOW)) return -EEXIST;
    if (errno!=ENOENT) return -errno;
    char path[PATH_MAX];
    int r=md_library_path(g->lib,g->group,name+11,path);
    if (!r) r=md_image_remove(path,g->layer);
    return r;
}
static int clean_input(int directory,const char *name,void *opaque) {
    const char *group=opaque;
    int work=!strcmp(group,"work"),names=!strcmp(group,"names");
    if (work) return !strncmp(name,"install-",8) ? md_private_tree_discard(directory,name) : 0;
    int match=names ? !strncmp(name,".publish-",9)
        : (strlen(name)==64 && strspn(name,"0123456789abcdef")==64) || !strncmp(name,".download-",10);
    if (!match) return 0;
    struct stat st;
    if (fstatat(directory,name,&st,AT_SYMLINK_NOFOLLOW)) return -errno;
    if (!S_ISREG(st.st_mode)) return -EINVAL;
    return unlinkat(directory,name,0) ? -errno : 0;
}
static int remove_layer(int directory,const char *name,void *opaque) {
    (void)directory;
    struct md_library *lib=opaque;
    if (is_stage(name)) return 0;
    char path[PATH_MAX];
    int r=md_library_path(lib,"layers",name,path);
    if (!r) r=exists(lib->json,"SELECT 1 FROM dependency JOIN resource ON resource.path=dependency.owner "
        "WHERE resource.retained=1 AND source=?1 LIMIT 1",path);
    if (r<0) return r;
    return r ? 0 : md_image_remove(path,1);
}
int md_library_prune(struct md_library *lib) {
    int r=0;
    const char *groups[]={"instances","images","layers"};
    for (size_t i=0; !r && i<3; ++i) {
        char path[PATH_MAX];
        r=md_library_path(lib,groups[i],NULL,path);
        if (!r) r=md_image_publish_recover(path);
        struct graph g={.lib=lib,.group=groups[i],.layer=i==2};
        if (!r) r=directory(lib,groups[i],finish_removal,&g);
    }
    if (!r) r=graph(lib,NULL);
    if (!r) r=plan(lib);
    /* Validate the complete dependency graph, including cycles, before removal. */
    sqlite3_stmt *q=NULL;
    if (!r) r=query(lib->json,"SELECT path FROM removal ORDER BY sequence",NULL,NULL,&q);
    int step=SQLITE_DONE;
    while (!r && (step=sqlite3_step(q))==SQLITE_ROW) r=md_image_remove((const char *)sqlite3_column_text(q,0),0);
    if (!r && step!=SQLITE_DONE) r=-EIO;
    sqlite3_finalize(q);
    if (!r) r=directory(lib,"layers",remove_layer,lib);
    const char *inputs[]={"names","work","cache"};
    for (size_t i=0; !r && i<3; ++i) r=directory(lib,inputs[i],clean_input,(void *)inputs[i]);
    return r;
}
