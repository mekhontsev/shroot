#define _GNU_SOURCE
#include "image_io.h"
#include "image_backup.h"
#include "image_oci_archive.h"
#include "image_json.h"
#include "image_layer.h"
#include "image_import.h"
#include "image_oci.h"
#include "image_publish.h"
#include "image_pool.h"
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int save(int directory, const char *name, const char *json) {
    int fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -errno;
    int r = md_image_write(fd, json, strlen(json));
    if (!r && fsync(fd)) r = -errno;
    close(fd); return r;
}
static int import_layout(int layout,int blobs,struct md_image_publish *publish,const char *reference,
        int preserve,const char *pool,int writable,int private_blobs) {
    int r=0;
    struct md_inode_store *store = NULL;
    if (!r) r = md_inode_store_open(publish->path, 1, &store);
    sqlite3 *json = NULL;
    if (!r && sqlite3_open(":memory:", &json) != SQLITE_OK) r = -ENOMEM;
    struct md_image_oci oci = {0};
    if (!r) r = md_image_oci_read(json, layout, blobs, private_blobs ? -1 : publish->stage, reference, &oci);
    char **diffs = NULL; size_t diff_count = 0;
    if (!r) r = md_json_array(json, oci.config, "$.rootfs.diff_ids", &diffs, &diff_count);
    int snapshot=0, guest_users=preserve;
    if (!r) r=md_oci_snapshot_policy(json,oci.manifest,diff_count,&snapshot,&guest_users);
    /* Snapshot metadata describes the published tree, not a reusable lower layer. */
    if (snapshot) { preserve=1; pool=NULL; }
    sqlite3_stmt *q = NULL;
    if (!r) r = md_json_query(json, oci.manifest, "SELECT json_type(?1,'$.layers')", &q);
    if (!r && (sqlite3_step(q) != SQLITE_ROW || sqlite3_column_type(q, 0) != SQLITE_TEXT
            || strcmp((const char *)sqlite3_column_text(q, 0), "array"))) r = -EINVAL;
    sqlite3_finalize(q); q = NULL;
    if (!r) r = md_json_query(json, oci.manifest, "SELECT type,value FROM json_each(?1,'$.layers')", &q);
    uint64_t bytes = 0, entries = 0;
    size_t layers = 0;
    while (!r) {
        int rc = sqlite3_step(q);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW || strcmp((const char *)sqlite3_column_text(q, 0), "object") || layers >= diff_count) {
            r = -EINVAL; break;
        }
        struct md_image_descriptor d = {0};
        r = md_image_descriptor_read(json, (const char *)sqlite3_column_text(q, 1), &d);
        int fd = -1;
        if (!r) r = md_image_unpack(blobs, publish->stage, private_blobs, &d, diffs[layers], &fd);
        struct md_image_pool shared = {.root=-1, .objects=-1};
        if (!r && pool) r = md_image_pool_open(pool, diffs[layers], fd, &shared);
        if (!r) r = pool ? md_image_layer_shared(store, fd, shared.objects, &bytes, &entries)
            : snapshot ? md_image_backup_tree(store, fd, &bytes, &entries) : md_image_layer(store, fd, &bytes, &entries);
        md_image_pool_close(&shared);
        if (fd >= 0) close(fd);
        md_image_descriptor_free(&d);
        ++layers;
    }
    sqlite3_finalize(q);
    if (!r && layers != diff_count) r = -EINVAL;
    if (!r) r = md_image_layers_finish(store, preserve);
    if (!r && snapshot && !guest_users) r=mdi_sql(store,"UPDATE properties SET value=0 WHERE key='image-users'");
    if (!r) r = save(store->lifetime->root, "image-config.json", oci.config);
    if (!r) r = save(store->lifetime->root, "image-manifest.json", oci.manifest);
    if (!r && !writable) r = md_inode_store_seal(store);
    if (!r && fsync(store->lifetime->root)) r = -errno;
    md_inode_store_close(store);
    if (json) sqlite3_close(json);
    if (!r) r = md_image_publish_commit(publish);
    if (!r) printf("Imported %s layers=%zu entries=%llu bytes=%llu identity=%s\n", oci.identity.digest,
        layers, (unsigned long long)entries, (unsigned long long)bytes, preserve ? "guest" : "current");
    md_json_array_free(diffs, diff_count); md_image_oci_free(&oci);
    return r;
}
int md_image_import_archive(int fd,struct md_image_publish *publish,const char *reference,int preserve,const char *pool,int writable) {
    int blobs=-1;
    int r=md_oci_archive_open(fd,publish->stage,&blobs);
    if (!r) r=import_layout(publish->stage,blobs,publish,reference,preserve,pool,writable,1);
    if (blobs>=0) close(blobs);
    return r;
}
int md_image_import(const char *source,const char *destination,const char *reference,int preserve,
        const char *pool,const char *blob_path) {
    int input=open(source,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (input<0) return -errno;
    struct stat st;
    int r=fstat(input,&st) ? -errno : 0;
    struct md_image_publish publish={.parent=-1,.stage=-1};
    if (!r) r=md_image_publish_begin(destination,&publish);
    if (!r && S_ISREG(st.st_mode)) {
        int snapshot=-1;
        r=blob_path ? -EINVAL : md_image_snapshot(input,publish.stage,MD_IMAGE_MAX_BYTES,&snapshot);
        if (!r) r=md_image_import_archive(snapshot,&publish,reference,preserve,pool,0);
        if (snapshot>=0) close(snapshot);
    } else if (!r && S_ISDIR(st.st_mode)) {
        int root=-1, blobs=-1;
        if (!blob_path && (root=openat(input,"blobs",O_DIRECTORY|O_RDONLY|O_NOFOLLOW|O_CLOEXEC))<0) r=-errno;
        if (!r && (blobs=openat(blob_path ? AT_FDCWD : root,blob_path ? blob_path : "sha256",
                O_DIRECTORY|O_RDONLY|O_NOFOLLOW|O_CLOEXEC))<0) r=-errno;
        if (!r) r=import_layout(input,blobs,&publish,reference,preserve,pool,0,0);
        if (blobs>=0) close(blobs);
        if (root>=0) close(root);
    } else if (!r) r=-EINVAL;
    md_image_publish_close(&publish); close(input); return r;
}
int md_image_create(const char *source, const char *destination) {
    struct md_inode_store *image = NULL, *instance = NULL;
    int r = md_inode_store_open(source, 0, &image);
    struct md_image_publish publish = {.parent=-1, .stage=-1};
    if (!r) r = md_image_publish_begin(destination, &publish);
    if (!r) r = md_inode_store_open(publish.path, 1, &instance);
    if (!r) r = md_inode_snapshot(image, instance);
    const char *files[] = {"image-config.json", "image-manifest.json"};
    for (unsigned i = 0; !r && i < sizeof(files)/sizeof(*files); ++i) {
        int fd = openat(image->lifetime->root, files[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) { if (i && errno == ENOENT) continue; r = -errno; break; }
        char *json = NULL;
        r = md_image_read(fd, 8*1024*1024, &json);
        if (!r) r = save(instance->lifetime->root, files[i], json);
        free(json); close(fd);
    }
    if (!r && fsync(instance->lifetime->root)) r = -errno;
    md_inode_store_close(instance); md_inode_store_close(image);
    if (!r) r = md_image_publish_commit(&publish);
    md_image_publish_close(&publish);
    if (!r) printf("Created instance %s\n", destination);
    return r;
}
