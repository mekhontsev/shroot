#define _GNU_SOURCE
#include "image_maintenance.h"
#include "image_publish.h"
#include "private_tree.h"
#include "storage_database.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int md_image_remove(const char *directory, int layer) {
    if (!directory || directory[0] != '/' || strlen(directory) >= PATH_MAX) return -EINVAL;
    char path[PATH_MAX]; strcpy(path, directory);
    char *name = strrchr(path, '/')+1;
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) return -EINVAL;
    if (layer && (strncmp(name, "layer-v1-", 9) || strlen(name+9) != 64
            || strspn(name+9, "0123456789abcdef") != 64)) return -EINVAL;
    char tomb[NAME_MAX+1], tomb_path[PATH_MAX];
    int length = snprintf(tomb, sizeof(tomb), ".md-remove-%s", name);
    if (length < 0 || length >= (int)sizeof(tomb)) return -ENAMETOOLONG;
    length = snprintf(tomb_path, sizeof(tomb_path), "%.*s%s", (int)(name-path), path, tomb);
    if (length < 0 || length >= (int)sizeof(tomb_path)) return -ENAMETOOLONG;
    struct stat present;
    int resumed = lstat(directory, &present) && errno == ENOENT;
    const char *selected = resumed ? tomb_path : directory;
    /* Deletion needs lifetime authority, not schema admission or source opens. */
    int root = open(selected, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int r = root < 0 ? -errno : 0;
    if (!r && flock(root, LOCK_EX | LOCK_NB)) r = errno == EWOULDBLOCK ? -EBUSY : -errno;
    int parent = -1;
    if (!r && (parent = openat(root, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) r = -errno;
    struct stat opened, named;
    if (!r && (fstat(root, &opened) || fstatat(parent, resumed ? tomb : name, &named, AT_SYMLINK_NOFOLLOW)
            || opened.st_dev != named.st_dev || opened.st_ino != named.st_ino)) r = -ESTALE;
    if (!r) {
        if (!resumed && syscall(SYS_renameat2, parent, name, parent, tomb, RENAME_NOREPLACE)) r = -errno;
        if (!r && fsync(parent)) r = -errno;
        if (!r) r = md_private_tree_discard(parent, tomb);
        if (!r && fsync(parent)) r = -errno;
    }
    if (parent >= 0) close(parent);
    if (root >= 0) close(root);
    return r;
}

int md_image_source_visit(const char *directory, int (*visit)(const char *,void *), void *opaque) {
    int root=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (root<0) return -errno;
    int r=flock(root,LOCK_SH|LOCK_NB) ? (errno==EWOULDBLOCK ? -EBUSY : -errno) : 0;
    sqlite3 *db=NULL;
    sqlite3_stmt *q=NULL;
    /* Dependencies are a persistent contract independent of runtime schema
     * admission. Do not open lower sources or require image configuration. */
    if (!r) r=md_database_open_readonly(root,"namespace.db",&db);
    if (!r) r=md_database_error(db,sqlite3_exec(db,"PRAGMA trusted_schema=OFF",NULL,NULL,NULL));
    if (!r) r=md_database_error(db,sqlite3_prepare_v2(db,"SELECT DISTINCT path FROM sources",-1,&q,NULL));
    int step=SQLITE_DONE;
    while (!r && (step=md_database_step(q))==SQLITE_ROW) {
        const char *path=(const char *)sqlite3_column_text(q,0);
        r=sqlite3_column_type(q,0)==SQLITE_TEXT && path && *path && strlen(path)==(size_t)sqlite3_column_bytes(q,0)
            ? visit(path,opaque) : -EINVAL;
    }
    if (!r && step!=SQLITE_DONE) r=step<0 ? step : -EIO;
    sqlite3_finalize(q);
    if (db) sqlite3_close(db);
    close(root); return r;
}

struct source_output { sqlite3_stmt *query; sqlite3_str *array; int count; };
static int source_json(const char *path,void *opaque) {
    struct source_output *out=opaque;
    int r=sqlite3_bind_text(out->query,1,path,-1,SQLITE_STATIC)==SQLITE_OK ? 0 : -ENOMEM;
    if (!r && sqlite3_step(out->query)!=SQLITE_ROW) r=-EIO;
    if (!r) {
        const char *json=(const char *)sqlite3_column_text(out->query,0);
        if (!json) r=-ENOMEM;
        else {
            if (out->count++) sqlite3_str_appendchar(out->array,1,',');
            sqlite3_str_appendall(out->array,json);
            if (sqlite3_str_errcode(out->array)!=SQLITE_OK) r=-ENOMEM;
        }
    }
    sqlite3_reset(out->query); sqlite3_clear_bindings(out->query); return r;
}
int md_image_sources(const char *directory) {
    sqlite3 *json=NULL;
    int r=sqlite3_open(":memory:",&json)==SQLITE_OK ? 0 : -ENOMEM;
    struct source_output out={.array=sqlite3_str_new(NULL)};
    if (!r && sqlite3_prepare_v2(json,"SELECT json_object('path',?1)",-1,&out.query,NULL)!=SQLITE_OK) r=-ENOMEM;
    sqlite3_str_appendchar(out.array,1,'[');
    if (!r) r=md_image_source_visit(directory,source_json,&out);
    sqlite3_str_appendchar(out.array,1,']');
    char *text=sqlite3_str_finish(out.array);
    if (!r && !text) r=-ENOMEM;
    if (!r && puts(text)==EOF) r=-EIO;
    sqlite3_free(text); sqlite3_finalize(out.query);
    if (json) sqlite3_close(json);
    return r;
}
