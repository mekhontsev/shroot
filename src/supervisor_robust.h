#ifndef MD_SUPERVISOR_ROBUST_H
#define MD_SUPERVISOR_ROBUST_H

#include "supervisor_thread.h"
#include "task_retained.h"
#include "task_robust.h"
#include "task_child_reap.h"

/* Private actors have wait ownership, never guest task/resource membership.
 * The mm pointer is borrowed from the attached guest tasks, not a writer pin. */
struct retained_memory {
    struct retained_memory *next,*work_next,*indexed;
    struct retained_memory *previous,*replacement;
    struct md_interception_memory *memory;
    struct md_task_wait_member wait;
    struct md_task_retained retained;
    struct md_task_robust cleanup;
    struct md_resource_order order;
    struct thread *creator, *terminal, *parent, *departing;
    int parent_exit_signal;
    unsigned members,pending;
    int ready, cleaning, retiring, dead, checkpoint_suspended, killed, exit_held,core_exit,queued;
    long error;
};

enum { RETAINED_ACTOR_BUCKETS=257 };

struct retained_retirement {
    struct retained_memory *memory;
    struct thread *actor;
    struct md_task_child_reap reap;
    struct md_task_child_reap_scratch scratch;
    struct md_interception_buffer buffer;
    struct md_resource_order order;
    uintptr_t peer;
    int stage, borrowed, synthetic, checkpoint_suspended, broker_borrowed;
    int child_notice;
};

extern struct retained_memory *retained_memories,*retained_creation,*retained_work;
extern struct retained_retirement *retained_retirement;
extern struct md_task_quiesce *retained_barrier;

int retained_task_held(const struct thread *t);
int retained_cleanup_pending(const struct thread *t);
void retained_publish_child_notice(pid_t recipient);
struct retained_memory *retained_actor(pid_t pid);
int retained_child_identity(const struct retained_memory *,pid_t *parent,pid_t *group,int *signal);
struct retained_memory *retained_memory_get(struct thread *t);
void retained_detach(struct thread *t);
enum retained_departure { RETAINED_EXIT=1, RETAINED_EXEC };
int retained_depart(struct thread *t,enum retained_departure);
int robust_call(struct thread *t,const struct seccomp_data *call,struct user_pt_regs *regs,enum md_task_call_boundary boundary);
struct md_process_query;
long robust_query(struct thread *,pid_t,struct md_process_query *);
void retained_creation_begin(struct retained_memory *m,struct thread *t,
        const struct user_pt_regs *regs,enum md_task_call_boundary call);
void retained_progress(void);
int retained_barrier_event(pid_t pid,int status,const struct rusage *usage);
void retained_barrier_blocked(pid_t pid);
int retained_runnable(void);
int retained_actor_exit(pid_t pid,int status);
pid_t retained_take(int *status,struct rusage *usage);
int retained_event(pid_t pid,int status,const struct rusage *usage);
void retained_cancel(void);
void retained_destroy(void);

#endif
