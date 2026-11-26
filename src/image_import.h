#ifndef SHROOT_IMAGE_IMPORT_H
#define SHROOT_IMAGE_IMPORT_H
#define MD_IMAGE_IMPORT_VERSION 1
int md_image_import(const char *layout, const char *destination, const char *reference,
    int preserve, const char *layers, const char *blobs);
struct md_image_publish;
int md_image_import_archive(int snapshot,struct md_image_publish *,const char *reference,int preserve,const char *pool,int writable);
int md_image_create(const char *source, const char *destination);
#endif
