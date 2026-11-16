#ifndef SHROOT_IMAGE_IMPORT_H
#define SHROOT_IMAGE_IMPORT_H
int md_image_import(const char *layout, const char *destination, const char *reference,
    int preserve, const char *layers, const char *blobs);
int md_image_create(const char *source, const char *destination);
#endif
