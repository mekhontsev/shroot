#ifndef MD_SUPERVISOR_IMAGE_H
#define MD_SUPERVISOR_IMAGE_H

struct thread;
int image_layout_prepare(const char *path);
int image_layout_begin(struct thread *);
int image_layout_event(struct thread *,int status);
void image_layout_discard(struct thread *);
void image_layout_release(void);

#endif
