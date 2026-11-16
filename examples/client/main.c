#include <shroot.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: shroot-inspect RUNTIME_DIRECTORY STORE\n");
        return 2;
    }
    shroot_context *context = NULL;
    shroot_store *store = NULL;
    shroot_job *job = NULL;
    int r = shroot_context_open(argv[1], &context);
    if (!r) r = shroot_store_open(context, argv[2], &store);
    if (!r) r = shroot_inspect(store, NULL, &job);
    struct shroot_result result = {0};
    if (!r) r = shroot_job_wait(job, 0, &result);
    if (job) {
        if (r) { shroot_job_cancel(job); shroot_job_wait(job, 0, &result); }
        shroot_job_close(job);
    }
    shroot_store_close(store); shroot_context_close(context);
    if (!r) r = result.error;
    if (r) fprintf(stderr, "shroot: %s\n", strerror(-r));
    return r || result.signal || result.exit_code ? 1 : 0;
}
