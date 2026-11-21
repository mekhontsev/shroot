#ifndef MD_IMAGE_PRESENTATION_H
#define MD_IMAGE_PRESENTATION_H
#include <stddef.h>
struct md_inode_store;
int md_image_os_info(const char *store);
int md_image_find_icon(struct md_inode_store *,const char **roots,unsigned count,const char *name,
    int branding,void *data,size_t limit);
#endif
