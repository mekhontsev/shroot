/* Exhaust all SC orders of one ready publication racing one park. Only the
 * scheduler and the kernel wait/wake effects are models: the parties below
 * call the same inline C helpers as the bootstrap and the broker. */
#include "cooperative_channel.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>

enum { WAITER, PUBLISHER, STEPS=6 };
static struct md_entry_channel channel;
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t turn=PTHREAD_COND_INITIALIZER;
static pthread_t sender;
static unsigned schedule,step;
static const char *trace[STEPS];

static void enter(const char *action) {
    unsigned actor=pthread_equal(pthread_self(),sender) ? PUBLISHER : WAITER;
    assert(!pthread_mutex_lock(&lock));
    /* EVENT_WAIT: the chosen actor runs its next step; CTest bounds a
     * production change that stops reaching the modelled boundaries. */
    while (step<STEPS && ((schedule>>step)&1)!=actor)
        assert(!pthread_cond_wait(&turn,&lock));
    assert(step<STEPS);
    trace[step]=action;
}
static void leave(void) {
    ++step;
    assert(!pthread_cond_broadcast(&turn));
    assert(!pthread_mutex_unlock(&lock));
}
static int scheduled_word(const atomic_uint *word) {
    return word==&channel.state || word==&channel.sleeping ||
        word==&channel.awake || word==&channel.control_awake;
}
static unsigned observe(const atomic_uint *word,memory_order order) {
    int scheduled=scheduled_word(word);
    if (scheduled) {
        assert(order==memory_order_seq_cst);
        enter(word==&channel.state ? "check-state" : "check-peer");
    }
    unsigned value=atomic_load_explicit(word,order);
    if (scheduled) leave();
    return value;
}
static void publish(atomic_uint *word,unsigned value,memory_order order) {
    assert(scheduled_word(word) && order==memory_order_seq_cst);
    enter(word==&channel.state ? "publish" : "arm-wait");
    atomic_store_explicit(word,value,order);
    leave();
}

/* Schedule the individual atomics, not just calls at the API boundary.
 * All dependencies were included above; no production hooks or fake loads. */
#pragma push_macro("atomic_load_explicit")
#pragma push_macro("atomic_store_explicit")
#undef atomic_load_explicit
#undef atomic_store_explicit
#define atomic_load_explicit(p,o) observe((p),(o))
#define atomic_store_explicit(p,v,o) publish((p),(v),(o))
#include "cooperative_exchange.h"
#pragma pop_macro("atomic_store_explicit")
#pragma pop_macro("atomic_load_explicit")

struct exchange {
    const char *name;
    enum md_entry_owner owner;
    unsigned from,to;
    int reply,native_sent;
};
static int drop_wake,asleep,queued;

static void *waiter(void *arg) {
    const struct exchange *x=arg;
    if (x->reply) {
        unsigned expected;
        int unannounced=0;
        int wait=md_entry_prepare_reply_wait(&channel,x->native_sent,&unannounced,&expected)==MD_REPLY_FUTEX;
        enter("compare-and-park");
        /* FUTEX_WAIT compares and enqueues indivisibly. An earlier wake
         * does not leave a credit for a later futex waiter. */
        asleep=wait && atomic_load(&channel.state)==expected;
    } else {
        unsigned ready=md_entry_prepare_wait(&channel,x->owner);
        enter("poll");
        asleep=!(ready&MD_ENTRY_PENDING_CALL) && !queued;
    }
    leave();
    return NULL;
}
static void publisher(const struct exchange *x) {
    int wake=x->reply ? md_entry_publish_response(&channel,x->to)
        : md_entry_publish_request(&channel,x->to);
    enter(!wake ? "no-wake" : drop_wake ? "DROP-wake" : "wake");
    if (wake && !drop_wake) {
        asleep=0;
        if (!x->reply) queued=1;
    }
    leave();
}
static void witness(const struct exchange *x,const char *reason) {
    fprintf(stderr,"%s: %s (schedule %#x):",x->name,reason,schedule);
    for (unsigned i=0;i<STEPS;++i) fprintf(stderr," %s",trace[i]);
    fputc('\n',stderr);
}
static void explore(const struct exchange *x) {
    for (drop_wake=0;drop_wake<=1;++drop_wake) {
        unsigned lost=0,orders=0;
        for (schedule=0;schedule<(1u<<STEPS);++schedule) {
            if (__builtin_popcount(schedule)!=3) continue;
            ++orders;
            atomic_store(&channel.state,x->from);
            atomic_store(&channel.awake,1); atomic_store(&channel.control_awake,1);
            atomic_store(&channel.sleeping,0);
            channel.call.reserved=x->owner==MD_ENTRY_SUPERVISOR_OWNER ? MD_ENTRY_BUFFER_CONTROL : MD_ENTRY_SYSCALL;
            step=0; queued=0; asleep=0;
            pthread_t peer;
            assert(!pthread_create(&peer,NULL,waiter,(void *)x));
            publisher(x);
            assert(!pthread_join(peer,NULL));
            assert(step==STEPS && atomic_load(&channel.state)==x->to);
            if (asleep) {
                if (!lost) witness(x,drop_wake ? "counterexample without wake" : "lost wake");
                ++lost;
            }
        }
        assert(orders==20);
        assert(drop_wake ? lost>0 : lost==0);
    }
}
void exchange_lifecycle_model(void);
int main(void) {
    sender=pthread_self();
    static const struct exchange cases[]={
        {"worker request",MD_ENTRY_WORKER_OWNER,MD_ENTRY_IDLE,MD_ENTRY_REQUEST,0,0},
        {"supervisor request",MD_ENTRY_SUPERVISOR_OWNER,MD_ENTRY_IDLE,MD_ENTRY_REQUEST,0,0},
        {"completed reply",0,MD_ENTRY_RUNNING,MD_ENTRY_RESPONSE,1,0},
        {"parked completion",0,MD_ENTRY_PARKED,MD_ENTRY_RESPONSE,1,0},
        {"native offer",0,MD_ENTRY_REQUEST,MD_ENTRY_NATIVE,1,0},
        {"native completion",0,MD_ENTRY_NATIVE,MD_ENTRY_RESPONSE,1,1},
    };
    for (unsigned i=0;i<sizeof(cases)/sizeof(*cases);++i) explore(&cases[i]);
    puts("PASS exchange model: all 20 schedules per handoff; dropping an obligatory wake strands the waiter");
    exchange_lifecycle_model();
    return 0;
}
