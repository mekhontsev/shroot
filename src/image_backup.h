#ifndef MD_IMAGE_BACKUP_H
#define MD_IMAGE_BACKUP_H
#include <string.h>
#define SHROOT_BACKUP_MANIFEST "shroot-backup.json"
#define SHROOT_BACKUP_MODE "shroot.backup.mode"
/* Archive v1 readers retain both spellings; storage family and identities do not change. */
static inline int md_backup_manifest(const char *name) {
    return name && (!strcmp(name, SHROOT_BACKUP_MANIFEST) || !strcmp(name, "magicdesk-backup.json"));
}
static inline int md_backup_mode(const char *name) {
    return name && (!strcmp(name, SHROOT_BACKUP_MODE) || !strcmp(name, "magicdesk.backup.mode"));
}
int md_image_backup(const char *store, const char *destination);
int md_image_archive_import(const char *archive, const char *destination, int backup);
/* Borrowed private, immutable snapshot; no second copy of a catalog input. */
int md_image_archive_snapshot(int snapshot, const char *destination, int backup);
#endif
