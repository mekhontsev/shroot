#ifndef MD_LAUNCH_IDENTITY_H
#define MD_LAUNCH_IDENTITY_H
#include "host_policy.h"
/* The caller selects authority. No set-id executable or per-operation elevation. */
static inline int md_launch_identity(long uid, long euid, long gid, long egid) {
#ifdef __ANDROID__
    return md_host_identity_admit(MD_HOST_ANDROID,uid,euid,gid,egid);
#else
    return md_host_identity_admit(MD_HOST_LINUX,uid,euid,gid,egid);
#endif
}
#endif
