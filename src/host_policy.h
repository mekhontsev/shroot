#ifndef MD_HOST_POLICY_H
#define MD_HOST_POLICY_H

/* Selected once by native launch admission, never by a guest request. */
extern int md_app_uid_active;
static inline int md_host_logical_sigsys(void) { return md_app_uid_active; }
enum md_host_platform { MD_HOST_LINUX, MD_HOST_ANDROID };
int md_host_identity_admit(enum md_host_platform, long uid, long euid, long gid, long egid);

#endif
