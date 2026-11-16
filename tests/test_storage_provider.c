#define _GNU_SOURCE
#include "storage_database.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void test_storage_database(void);
int main(int argc,char **argv) {
    alarm(60);
    if (argc==2 && !strcmp(argv[1],"--reject")) {
        int directory=open(".",O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(directory>=0);
        assert(faccessat(directory,"unsupported.db",F_OK,0)<0 && errno==ENOENT);
        sqlite3 *db=NULL;
        assert(md_database_open(directory,"unsupported.db",1,&db)==-ENOTSUP && !db);
        assert(md_database_open_readonly(directory,"unsupported.db",&db)==-ENOTSUP && !db);
        assert(md_database_temporary_directory(NULL)==-ENOTSUP);
        assert(faccessat(directory,"unsupported.db",F_OK,0)<0 && errno==ENOENT);
        close(directory);
        puts("PASS incompatible SQLite rejected before persistent storage changes");
    } else {
        assert(argc==1);
        test_storage_database();
    }
    return 0;
}
