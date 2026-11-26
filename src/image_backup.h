#ifndef MD_IMAGE_BACKUP_H
#define MD_IMAGE_BACKUP_H
#define SHROOT_SNAPSHOT "io.github.mekhontsev.shroot.snapshot"
#define SHROOT_GUEST_USERS "io.github.mekhontsev.shroot.guest-users"
int md_image_backup(const char *store, const char *destination);
int md_image_archive_import(const char *archive, const char *destination, int backup);
/* Borrowed private, immutable snapshot; no second copy of a catalog input. */
int md_image_archive_snapshot(int snapshot, const char *destination, int backup);
#endif
