#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <linux/capability.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

/* getuid ignores its arguments, but seccomp sees them. Only tag the test call
 * so that installing the policy cannot change the launcher's own uid queries. */
#define POLICY_UID_TAG 0x51a77001UL

static int check_policy(int denied) {
    int mode=prctl(PR_GET_SECCOMP,0,0,0,0), published=-1, filters=-1;
    FILE *status=fopen("/proc/self/status","r");
    if (!status) { perror("policy status"); return 1; }
    char line[256];
    while (fgets(line,sizeof(line),status)) {
        (void)sscanf(line,"Seccomp: %d",&published);
        (void)sscanf(line,"Seccomp_filters: %d",&filters);
    }
    int error=ferror(status);
    if (fclose(status) || error || mode!=published || filters<0
            || (mode!=0 && mode!=SECCOMP_MODE_FILTER) || (!!mode!=!!filters) || (denied && !mode)) {
        fprintf(stderr,"policy view: prctl=%d status=%d filters=%d denied=%d\n",mode,published,filters,denied);
        return 1;
    }
    errno=0;
    long priority=syscall(SYS_getpriority,PRIO_PROCESS,0);
    if (denied ? priority!=-1 || errno!=EACCES : priority<0) {
        fprintf(stderr,"getpriority: result=%ld errno=%d denied=%d\n",priority,errno,denied); return 1;
    }
    long uid=syscall(SYS_getuid,0L,0L,0L,0L,0L,0L);
    if (uid<0) { perror("getuid control"); return 1; }
    for (unsigned i=0;i<34;++i) {
        unsigned long tag=i==32 ? POLICY_UID_TAG : 0;
        errno=0;
        long result=syscall(SYS_getuid,tag,0L,0L,0L,0L,0L);
        int expect_denial=tag && denied;
        if (expect_denial ? result!=-1 || errno!=EACCES : result!=uid) {
            fprintf(stderr,"getuid: iteration=%u result=%ld errno=%d denied=%d\n",
                    i,result,errno,expect_denial); return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc>=3 && (!strcmp(argv[1],"exec-nnp") || !strcmp(argv[1],"exec-deny-priority"))) {
        if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)<0) { perror("set no_new_privs"); return 1; }
        if (!strcmp(argv[1],"exec-deny-priority")) {
            struct sock_filter code[]={
                BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
                BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getpriority,3,0),
                BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getuid,0,3),
                BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
                BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,POLICY_UID_TAG,0,1),
                BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
                BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
            };
            struct sock_fprog program={sizeof(code)/sizeof(*code),code};
            if (prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)<0) { perror("install test policy"); return 1; }
        }
        execv(argv[2],argv+2); perror("exec policy test"); return 1;
    }
    if (argc==2 && (!strcmp(argv[1],"priority-allowed") || !strcmp(argv[1],"priority-denied"))) {
        if (prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1) { fputs("no_new_privs was not inherited\n",stderr); return 1; }
        int denied=!strcmp(argv[1],"priority-denied");
        if (check_policy(denied)) return 1;
        if (denied) {
            struct sock_filter allow=BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
            struct sock_fprog suffix={1,&allow};
            if (prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&suffix)<0) { perror("extend test policy"); return 1; }
            if (check_policy(denied)) return 1;
            int fd=open(argv[0],O_RDONLY|O_CLOEXEC);
            char header[4];
            if (fd<0) { perror("open executable under stacked policy"); return 1; }
            if (read(fd,header,sizeof(header))!=sizeof(header) || memcmp(header,"\177ELF",4) || close(fd)) {
                fputs("no executable descriptor under stacked policy\n",stderr); return 1;
            }
            int ep=epoll_create1(EPOLL_CLOEXEC), ready=eventfd(1,EFD_CLOEXEC);
            struct epoll_event watch={.events=EPOLLIN,.data.u64=42}, event={0};
            if (ep<0 || ready<0 || epoll_ctl(ep,EPOLL_CTL_ADD,ready,&watch)<0
                    || epoll_pwait(ep,&event,1,0,NULL)!=1 || !(event.events&EPOLLIN)
                    || event.data.u64!=42 || close(ready) || close(ep)) {
                fputs("epoll readiness lost under stacked policy\n",stderr); return 1;
            }
        }
        puts(argv[1]); return 0;
    }
    if (argc==2 && !strcmp(argv[1],"external-folders")) {
        const char *rw="/mnt/android/Work",*ro="/mnt/android/Read only";
        int wd=open(rw,O_RDONLY|O_DIRECTORY),rd=open(ro,O_RDONLY|O_DIRECTORY);
        if (wd<0 || rd<0) { perror("open mount roots"); return 1; }
        DIR *names=fdopendir(dup(rd));
        if (!names) { perror("read directory"); return 1; }
        int found=0;
        struct dirent *entry;
        while ((entry=readdir(names))) found+=!strcmp(entry->d_name,"token");
        if (closedir(names) || found!=1) { fprintf(stderr,"expected token once, found %d\n",found); return 1; }
        int a=openat(wd,"token",O_RDWR),b=openat(rd,"token",O_RDONLY);
        char data[9];
        if (a<0 || b<0 || pread(b,data,9,0)!=9 || memcmp(data,"read-only",9)
                || pwrite(a,"updated",7,0)!=7) { perror("folder IO"); return 1; }
        if (openat(rd,"token",O_RDWR)>=0 || errno!=EROFS) { perror("read-only open"); return 1; }
        if (!mount(NULL,ro,NULL,MS_REMOUNT|MS_BIND|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)) return 1;
        if (close(a) || close(b) || close(rd) || close(wd) || umount(ro)) { perror("unmount"); return 1; }
        if (!access("/mnt/android/Read only/token",F_OK) || errno!=ENOENT || access("/mnt/android/Work/token",F_OK)) return 1;
        puts("PASS external FUSE: independent mounts, data, locked ro and ordinary umount"); return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "reserve-large-range")) {
        size_t length = ((size_t)256 << 30) + sysconf(_SC_PAGESIZE);
        void *area = mmap(NULL, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (area == MAP_FAILED) {
            if (errno == ENOMEM) return 77;
            perror("reserve large address range");
            return 1;
        }
        return munmap(area, length) ? 1 : 0;
    }
    if (argc == 3 && !strcmp(argv[1], "fork-exec")) {
        pid_t child = fork();
        if (child < 0) return 12;
        if (!child) {
            char *next[] = {argv[0], argv[2], NULL};
            execv(next[0], next);
            _exit(13);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 14;
        return WEXITSTATUS(status);
    }
    if (argc == 3 && !strcmp(argv[1], "path")) {
        const char *path = getenv("PATH");
        return !path || strcmp(path, argv[2]) ? 40 : 0;
    }
    if (argc == 3 && !strcmp(argv[1], "readonly-bind")) {
        char path[256], data[16] = {0};
        if (snprintf(path, sizeof(path), "%s/token", argv[2]) >= (int)sizeof(path)) return 30;
        int fd = open(path, O_RDONLY);
        if (fd < 0 || read(fd, data, sizeof(data)) != 9 || memcmp(data, "read-only", 9)) return 31;
        close(fd);
        fd = open(path, O_WRONLY);
        if (fd >= 0 || errno != EROFS) return 32;
        fd = open(argv[2], O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
        if (fd >= 0 || errno != EROFS) { perror("guest readonly tmpfile"); return 33; }
        puts("PASS guest: created readonly attachment, contents and write denial");
        return 0;
    }
    if ((argc == 3 || argc == 5) && !strcmp(argv[1], "native-tmpfile")) {
        mode_t mask = umask(0077);
        int errors[2] = {0};
        for (unsigned exclusive = 0; exclusive < 2; ++exclusive) {
            int fd = open(argv[2], O_TMPFILE | O_RDWR | O_CLOEXEC | (exclusive ? O_EXCL : 0), 0666);
            errors[exclusive] = fd < 0 ? errno : 0;
            if (argc == 5 && errors[exclusive] != atoi(argv[3 + exclusive])) {
                fprintf(stderr, "temporary file exclusive=%u expected errno=%s actual=%d\n",
                        exclusive, argv[3 + exclusive], errors[exclusive]);
                if (fd >= 0) close(fd);
                return 34;
            }
            /* Bind attachments retain their source filesystem capabilities.
             * Record unsupported O_TMPFILE, not unrelated IO/permission errors. */
            if (fd < 0 && (errno == EOPNOTSUPP || errno == EINVAL || errno == EISDIR)) continue;
            struct stat st;
            if (fd < 0 || fstat(fd, &st)) { perror("guest native tmpfile"); return 34; }
            if (!S_ISREG(st.st_mode) || (st.st_mode & 0777) != 0600 || st.st_nlink
                    || fcntl(fd, F_GETFD) != FD_CLOEXEC) return 35;
            char value = 0;
            if (write(fd, "x", 1) != 1 || pread(fd, &value, 1, 0) != 1 || value != 'x'
                    || close(fd)) return 36;
        }
        umask(mask);
        printf("[%d,%d]\n", errors[0], errors[1]);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "publish-tmpfile")) {
        int dir=open(argv[2],O_DIRECTORY|O_RDONLY|O_CLOEXEC);
        int fd=openat(dir,".",O_TMPFILE|O_RDWR|O_CLOEXEC,0600);
        struct stat before,after;
        if (fd<0 || fstat(fd,&before) || before.st_nlink || write(fd,"A",1)!=1) {
            perror("prepare tmpfile"); return 37;
        }
        pid_t child=fork();
        if (!child) {
            char proc[64];
            snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
            if (!linkat(AT_FDCWD,proc,AT_FDCWD,"/native-alias/escaped",AT_SYMLINK_FOLLOW)
                    || errno!=EXDEV) { perror("publish across attachments"); _exit(38); }
            if (!linkat(AT_FDCWD,proc,dir,"nofollow",0)) _exit(38);
            if (!linkat(AT_FDCWD,proc,dir,"token",AT_SYMLINK_FOLLOW) || errno!=EEXIST) {
                perror("publish to occupied name"); _exit(38);
            }
            if (linkat(AT_FDCWD,proc,dir,"published",AT_SYMLINK_FOLLOW)) {
                perror("publish tmpfile"); _exit(39);
            }
            _exit(0);
        }
        int status;
        if (child<0 || waitpid(child,&status,0)!=child || status) return 38;
        if (fstat(fd,&after) || after.st_nlink!=1 || write(fd,"B",1)!=1 ||
                fstatat(dir,"published",&after,AT_SYMLINK_NOFOLLOW) ||
                after.st_ino!=before.st_ino || after.st_dev!=before.st_dev) return 39;
        int exclusive=openat(dir,".",O_TMPFILE|O_EXCL|O_RDWR,0600);
        if (exclusive<0) return 39;
        char proc[64]; snprintf(proc,sizeof(proc),"/proc/self/fd/%d",exclusive);
        if (!linkat(AT_FDCWD,proc,dir,"exclusive",AT_SYMLINK_FOLLOW) || close(exclusive)) return 39;
        int direct=openat(dir,".",O_TMPFILE|O_RDWR,0600);
        struct __user_cap_header_struct header={.version=_LINUX_CAPABILITY_VERSION_3};
        struct __user_cap_data_struct caps[2];
        if (direct<0 || syscall(SYS_capget,&header,caps)) return 39;
        int rc=linkat(direct,"",dir,"direct",AT_EMPTY_PATH);
        if (caps[0].effective&(1U<<CAP_DAC_READ_SEARCH)) {
            if (rc || unlinkat(dir,"direct",0)) { perror("privileged empty-path link"); return 39; }
        } else if (!rc || errno!=ENOENT) { perror("unprivileged empty-path link"); return 39; }
        if (fstat(direct,&after) || after.st_nlink || close(direct)) return 39;
        return close(fd) || close(dir);
    }
    if (argc == 2 && !strcmp(argv[1], "limits")) {
        struct rlimit limit;
        if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur != 128 || limit.rlim_max != 4096) return 20;
        limit.rlim_cur = limit.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &limit)) return 21;
        int descriptors[256];
        for (unsigned i = 0; i < sizeof(descriptors)/sizeof(*descriptors); ++i) {
            descriptors[i] = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
            if (descriptors[i] < 0) {
                fprintf(stderr,"guest netlink budget index=%u errno=%d\n",i,errno);
                perror("guest netlink budget"); return 22;
            }
        }
        for (unsigned i = 0; i < sizeof(descriptors)/sizeof(*descriptors); ++i)
            if (close(descriptors[i])) return 23;
        puts("PASS guest limits: inherited soft/hard, raised soft, independent service budget");
        return 0;
    }
    if (argc == 2 && (!strcmp(argv[1], "hold") || !strcmp(argv[1], "hold-owner"))) {
        if (!strcmp(argv[1], "hold-owner")) for (int i = 4; i <= 5; ++i)
            if (fcntl(i, F_GETFD) >= 0 || errno != EBADF) return 41;
        if (fork() < 0) return 10;
        if (write(1, "ready\n", 6) != 6) return 11;
        for (;;) pause();
    }
    if (argc == 2 && !strcmp(argv[1], "exit42")) return 42;
    if (argc != 2 || strcmp(argv[1], "spaces ' ; $(false)")) return 1;
    const char *value = getenv("LIBSHROOT_TEST");
    if (!value || strcmp(value, "retained ' value")) return 2;
    struct stat a, b;
    if (stat("/payload", &a) || stat("/hardlink", &b) || a.st_ino != b.st_ino || a.st_nlink != 2) return 3;
    int fd = open("/link", O_RDONLY);
    char data[64] = {0};
    if (fd < 0 || read(fd, data, sizeof(data)-1) != 17 || strcmp(data, "libshroot payload")) return 4;
    close(fd);
    if (fcntl(123, F_GETFD) >= 0 || errno != EBADF) return 5;
    puts("PASS guest: arguments, environment, metadata and descriptor isolation");
    return 0;
}
