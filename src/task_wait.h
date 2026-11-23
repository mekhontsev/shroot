#ifndef MD_TASK_WAIT_H
#define MD_TASK_WAIT_H
#include <sys/resource.h>
#include <sys/types.h>

/* SIGCHLD is a lossy hint, never ownership or proof of a stopped task.
 * Collected statuses remain owned here until returned exactly once. */
struct md_task_wait_member {
    struct md_task_wait_member *next, *previous;
    pid_t pid;
    struct md_task_wait_member *guard_next;
    enum { MD_EXIT_DELIVER, MD_EXIT_GUARDED, MD_EXIT_OBSERVED } exit_state;
};
struct md_task_wait {
    struct md_task_wait_member *cursor;
    struct md_task_wait_member *guarded;
    struct md_task_wait_exit *exit_first, *exit_last;
    pid_t hints[8];
    pid_t recent[4];
    unsigned first, count;
    unsigned directed, fair_phase;
    unsigned members, pending_first, pending_count;
    struct {
        pid_t pid;
        int status;
        struct rusage usage;
    } pending[32];
    int drained, batch;
};
void md_task_wait_track(struct md_task_wait *, struct md_task_wait_member *, pid_t);
void md_task_wait_untrack(struct md_task_wait *, struct md_task_wait_member *);
/* A private child's final status proves it has dropped its mm. Leave it in
 * the kernel until its signal/reaping owner admits publication to the parent.
 * Stops remain consumable. First observation invalidates the event loop's
 * empty observation (EINTR); release makes the original status collectible. */
void md_task_wait_guard_exit(struct md_task_wait *,struct md_task_wait_member *);
void md_task_wait_release_exit(struct md_task_wait *,struct md_task_wait_member *);
void md_task_wait_hint(struct md_task_wait *, pid_t);
/* An observed SIGCHLD invalidates a drained queue even without a visible
 * sender. An empty directed hint alone is not a wake. */
void md_task_wait_sigchld(struct md_task_wait *,pid_t);
/* Make an already terminal tracee waitable by its real parent. Its separate
 * tracer status still passes through the normal event and accounting owner. */
int md_task_wait_handoff_exit(struct md_task_wait *, pid_t);
/* Transfer an already collected status, including during fatal cleanup.
 * Never queries the kernel or infers that its event queue is empty. */
pid_t md_task_wait_take(struct md_task_wait *, int *, struct rusage *);
/* Nonblocking __WALL wait with bounded preference for notified TIDs.
 * A general empty result remains valid until SIGCHLD invalidates it. Callers
 * must service the blocked signal source and include it in readiness waits.
 * Runnable callers guarantee another discovery pass before parking. They may
 * receive zero after a directed miss without a general empty observation;
 * the finite discovery budget still bounds untracked births and lost hints.
 * Pass runnable=0 before waiting on external events. Positive results, errors
 * and accounting are the unmodified wait4 result. */
pid_t md_task_wait_ready(struct md_task_wait *, int *, struct rusage *, int runnable);
#endif
