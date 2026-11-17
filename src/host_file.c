#define _GNU_SOURCE
#include "host_open.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>

long md_host_rename(int source,const char *name,int target,const char *next,unsigned flags) {
    return RAW5(renameat2,source,name,target,next,flags);
}

long md_host_temporary(int base,const char *path,unsigned mode) {
    long fd=RAW4(openat,base,path,O_TMPFILE|O_RDWR|O_CLOEXEC,mode);
    if (fd!=-EOPNOTSUPP && fd!=-EINVAL && fd!=-EISDIR) return fd;
    long directory=RAW4(openat,base,path,O_PATH|O_DIRECTORY|O_CLOEXEC,0);
    if (directory<0) return directory;
    enum { PREFIX=sizeof(".shroot-tmp-")-1 };
    char name[PREFIX+32+1]=".shroot-tmp-";
    for (;;) {
        unsigned char random[16];
        size_t used=0;
        while (used<sizeof(random)) {
            long n=RAW3(getrandom,random+used,sizeof(random)-used,0);
            if (n==-EINTR) continue;
            if (n<=0) { fd=n ? n : -EIO; goto done; }
            used+=(size_t)n;
        }
        for (unsigned i=0;i<sizeof(random);++i) {
            name[PREFIX+2*i]="0123456789abcdef"[random[i]>>4];
            name[PREFIX+1+2*i]="0123456789abcdef"[random[i]&15];
        }
        fd=RAW4(openat,directory,name,O_CREAT|O_EXCL|O_NOFOLLOW|O_RDWR|O_CLOEXEC,mode);
        if (fd==-EEXIST) continue;
        if (fd>=0) {
            long error=RAW3(unlinkat,directory,name,0);
            if (error) { RAW1(close,fd); fd=error; }
        }
        break;
    }
done:
    RAW1(close,directory);
    return fd;
}
