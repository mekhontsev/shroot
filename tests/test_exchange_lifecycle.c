/* Topological schedules at channel-operation boundaries. The broker lock
 * serializes admissions; the native effect and its kernel transport are inputs.
 * The single-handoff model separately schedules the individual park atomics. */
#include "cooperative_exchange.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

enum event { RETIRE_A, RELEASE_A, TAKE_A, TRY_FD, WITHDRAW_FD, POST_B, ARM_B, ADMIT_B, REPLY_B, TAKE_B, EVENTS };
#define BIT(e) (1u<<(e))
static const char *const names[]={"retire-A","wake/release-A","take-A","try-FD","withdraw-FD",
    "post-B","arm-B","admit-B","reply-B","take-B"};
struct experiment {
    uint64_t previous;
    unsigned kind;
    int cancel_a,withdraw;
    enum event path[EVENTS];
    unsigned schedules,late_retire,late_wake;
};
static void failure(const struct experiment *x,unsigned length,const char *invariant) {
    fprintf(stderr,"exchange lifecycle: %s (previous=%llu kind=%u cancel=%d withdraw=%d):",
        invariant,(unsigned long long)x->previous,x->kind,x->cancel_a,x->withdraw);
    for (unsigned i=0;i<length;++i) fprintf(stderr," %s",names[x->path[i]]);
    fputc('\n',stderr); abort();
}
#define REQUIRE(expr) do { if (!(expr)) failure(x,i+1,#expr); } while (0)

static void replay(struct experiment *x,unsigned length) {
    struct md_entry_channel c={0};
    uint64_t a=x->previous+1,b=a+1,admitted=a;
    enum md_entry_outcome outcome_a=x->cancel_a ? MD_ENTRY_DECLINED : MD_ENTRY_COMPLETED;
    long result_a=x->cancel_a ? -EINTR : 41;
    /* A was admitted; its effect has either completed or been cancelled
     * before execution. The caller and worker may now race for its result. */
    c.sequence=a; c.native.result=result_a;
    atomic_store(&c.native.state,x->cancel_a ? MD_NATIVE_CANCELLED : MD_NATIVE_DONE);
    atomic_store(&c.state,MD_ENTRY_NATIVE);
    if (x->cancel_a) {
        long untouched=-123;
        assert(!md_entry_early_native_result(&c,&untouched) && untouched==-123);
        assert(atomic_load(&c.state)==MD_ENTRY_NATIVE);
    }
    unsigned done=0,expected;
    int notify_a=0,sleeping_b=0;
    for (unsigned i=0;i<length;++i) {
        enum event e=x->path[i];
        enum md_entry_outcome outcome=MD_ENTRY_UNKNOWN;
        long result=-999;
        switch (e) {
        case RETIRE_A:
            notify_a=md_entry_native_retire(&c,a,outcome_a,result_a);
            REQUIRE(notify_a==!(done&BIT(TAKE_A)));
            if (done&BIT(POST_B)) ++x->late_retire;
            break;
        case RELEASE_A:
            /* This wake belongs to A's publication but addresses the shared
             * futex. B must recheck and park again, not consume A's receipt. */
            if (notify_a && atomic_load(&c.sleeping) && sleeping_b) {
                ++x->late_wake;
                atomic_store(&c.sleeping,0);
                REQUIRE(md_entry_prepare_reply_wait(&c,0,&expected) && expected==MD_ENTRY_REQUEST);
            }
            break;
        case TAKE_A:
            if (md_entry_early_native_result(&c,&result)) {
                REQUIRE(!x->cancel_a && !(done&BIT(RETIRE_A)) && result==result_a);
            } else {
                REQUIRE(atomic_load(&c.state)==MD_ENTRY_RESPONSE);
                REQUIRE(md_entry_read_reply(&c,&outcome,&result) && outcome==outcome_a && result==result_a);
                atomic_store(&c.state,MD_ENTRY_IDLE);
            }
            break;
        case TRY_FD:
            c.input.sequence=++c.sequence; c.call.reserved=MD_ENTRY_SYSCALL;
            c.call.args[0]=11;
            md_entry_publish_request(&c,MD_ENTRY_FD_REQUEST);
            REQUIRE(c.sequence==b && md_entry_fd_pending(atomic_load(&c.state)));
            break;
        case WITHDRAW_FD:
            REQUIRE(md_entry_withdraw_fd(&c));
            REQUIRE(c.sequence==a && !c.input.sequence && admitted==a);
            REQUIRE(atomic_load(&c.state)==((done&BIT(RETIRE_A)) ? MD_ENTRY_IDLE : MD_ENTRY_RETIRING));
            break;
        case POST_B:
            ++c.sequence; c.call.reserved=x->kind; c.call.args[0]=73;
            md_entry_publish_request(&c,MD_ENTRY_REQUEST);
            REQUIRE(c.sequence==b && !c.input.sequence);
            break;
        case ARM_B:
            sleeping_b=md_entry_prepare_reply_wait(&c,0,&expected);
            REQUIRE(sleeping_b==!(done&BIT(REPLY_B)));
            break;
        case ADMIT_B: {
            enum md_entry_owner owner=md_entry_request_owner(x->kind);
            REQUIRE(md_entry_prepare_wait(&c,owner)&MD_ENTRY_PENDING_CALL);
            REQUIRE(md_entry_next_sequence(admitted,c.sequence) && c.call.args[0]==73);
            admitted=c.sequence;
            atomic_store(&c.state,MD_ENTRY_RUNNING);
            break;
        }
        case REPLY_B:
            md_entry_record_reply(&c,admitted,MD_ENTRY_COMPLETED,(long)c.call.args[0]);
            if (md_entry_publish_response(&c,MD_ENTRY_RESPONSE)) sleeping_b=0;
            break;
        case TAKE_B:
            REQUIRE(!sleeping_b && atomic_load(&c.state)==MD_ENTRY_RESPONSE);
            REQUIRE(md_entry_read_reply(&c,&outcome,&result) && outcome==MD_ENTRY_COMPLETED && result==73);
            atomic_store(&c.sleeping,0); atomic_store(&c.state,MD_ENTRY_IDLE);
            break;
        default: abort();
        }
        done|=BIT(e);
        if ((done&BIT(POST_B)) && !(done&BIT(REPLY_B))) {
            /* Independent oracle: a stale completion must neither answer B
             * nor erase its readiness or its captured payload. */
            REQUIRE(atomic_load(&c.state)==((done&BIT(ADMIT_B)) ? MD_ENTRY_RUNNING : MD_ENTRY_REQUEST));
            REQUIRE(c.sequence==b && c.call.reserved==x->kind && c.call.args[0]==73);
        }
    }
    ++x->schedules;
}
static void explore(struct experiment *x,unsigned done,unsigned depth) {
    const unsigned requires[EVENTS]={
        [RELEASE_A]=BIT(RETIRE_A), [TAKE_A]=x->cancel_a ? BIT(RETIRE_A) : 0,
        [TRY_FD]=BIT(TAKE_A), [WITHDRAW_FD]=BIT(TRY_FD),
        [POST_B]=x->withdraw ? BIT(WITHDRAW_FD) : BIT(TAKE_A), [ARM_B]=BIT(POST_B),
        [ADMIT_B]=BIT(POST_B)|BIT(RELEASE_A), [REPLY_B]=BIT(ADMIT_B),
        [TAKE_B]=BIT(REPLY_B)|BIT(ARM_B)
    };
    if (done==(1u<<EVENTS)-1) { replay(x,depth); return; }
    for (enum event e=0;e<EVENTS;++e) {
        if ((done&BIT(e)) || (requires[e]&~done)) continue;
        x->path[depth]=e;
        explore(x,done|BIT(e),depth+1);
    }
}
void exchange_lifecycle_model(void) {
    struct md_entry_channel c={.sequence=2};
    enum md_entry_outcome outcome=MD_ENTRY_UNKNOWN;
    long result=-123;
    md_entry_record_reply(&c,1,MD_ENTRY_COMPLETED,41);
    md_entry_publish_response(&c,MD_ENTRY_RESPONSE);
    assert(!md_entry_read_reply(&c,&outcome,&result) && result==-123 && outcome==MD_ENTRY_UNKNOWN);
    assert(!md_entry_next_sequence(UINT64_MAX,0) && !md_entry_next_sequence(1,1));
    unsigned schedules=0,late_retire=0,late_wake=0;
    for (unsigned config=0;config<16;++config) {
        struct experiment x={.previous=(config&1) ? UINT64_MAX-2 : 0,
            .kind=(config&2) ? MD_ENTRY_BUFFER_CONTROL : MD_ENTRY_SYSCALL,
            .cancel_a=!!(config&4),.withdraw=!!(config&8)};
        explore(&x,x.withdraw ? 0 : BIT(TRY_FD)|BIT(WITHDRAW_FD),0);
        assert(x.schedules && x.late_wake && (x.cancel_a || x.late_retire));
        schedules+=x.schedules; late_retire+=x.late_retire; late_wake+=x.late_wake;
    }
    printf("PASS exchange lifecycle: %u schedules, %u late retirements, %u stale wakes during B's wait\n",
        schedules,late_retire,late_wake);
}
