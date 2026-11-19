#ifndef MD_COOPERATIVE_EXCHANGE_H
#define MD_COOPERATIVE_EXCHANGE_H
#include "cooperative_channel.h"

/* One shared protocol, two execution owners. This layer publishes readiness;
 * its caller owns kernel wakeups, operation lifetime and effect cancellation. */
enum md_entry_owner { MD_ENTRY_WORKER_OWNER, MD_ENTRY_SUPERVISOR_OWNER };
/* Only these states let the caller publish another request without an owner
 * response. RUNNING belongs to an asynchronous handler, not a hot peer. */
static inline int md_entry_peer_runnable(unsigned state) {
    return state==MD_ENTRY_IDLE || state==MD_ENTRY_RESPONSE
        || state==MD_ENTRY_NATIVE || state==MD_ENTRY_RETIRING;
}
static inline enum md_entry_owner md_entry_request_owner(unsigned kind) {
    return md_entry_control_request(kind) ? MD_ENTRY_SUPERVISOR_OWNER : MD_ENTRY_WORKER_OWNER;
}
static inline atomic_uint *md_entry_owner_awake(struct md_entry_channel *c,enum md_entry_owner owner) {
    return owner==MD_ENTRY_SUPERVISOR_OWNER ? &c->control_awake : &c->awake;
}
static inline int md_entry_fd_pending(unsigned state) {
    return state==MD_ENTRY_FD_REQUEST || state==MD_ENTRY_FD_RETIRING;
}
static inline int md_entry_next_sequence(uint64_t previous,uint64_t sequence) {
    return previous!=UINT64_MAX && sequence==previous+1;
}
static inline void md_entry_record_reply(struct md_entry_channel *c,uint64_t sequence,
        enum md_entry_outcome outcome,long result) {
    c->receipt=sequence; c->outcome=outcome; c->result=result;
}
/* The caller has acquired RESPONSE. A wake alone never admits these fields. */
static inline int md_entry_read_reply(const struct md_entry_channel *c,enum md_entry_outcome *outcome,long *result) {
    if (c->receipt!=c->sequence) return 0;
    *outcome=c->outcome; *result=c->result;
    return 1;
}
/* Either publication observes a parked owner or parking observes the request.
 * The returned wake obligation must be fulfilled by the caller's transport. */
static inline int md_entry_publish_request(struct md_entry_channel *c,unsigned state) {
    atomic_uint *awake=md_entry_owner_awake(c,md_entry_request_owner(c->call.reserved));
    if (state==MD_ENTRY_FD_REQUEST) {
        /* Withdrawal must preserve an older effect's retirement. Its owner
         * may finish concurrently with this next request's publication. */
        unsigned previous=atomic_load_explicit(&c->state,memory_order_acquire);
        do {
            state=previous==MD_ENTRY_RETIRING ? MD_ENTRY_FD_RETIRING : MD_ENTRY_FD_REQUEST;
        } while (!atomic_compare_exchange_weak_explicit(&c->state,&previous,state,
            memory_order_seq_cst,memory_order_acquire));
    } else atomic_store_explicit(&c->state,state,memory_order_seq_cst);
    return !atomic_load_explicit(awake,memory_order_seq_cst);
}
static inline int md_entry_withdraw_fd(struct md_entry_channel *c) {
    unsigned pending=atomic_load_explicit(&c->state,memory_order_acquire);
    while (md_entry_fd_pending(pending)) {
        unsigned previous=pending==MD_ENTRY_FD_RETIRING ? MD_ENTRY_RETIRING : MD_ENTRY_IDLE;
        if (atomic_compare_exchange_weak_explicit(&c->state,&pending,previous,
                memory_order_acq_rel,memory_order_acquire)) {
            /* Only an unadmitted sequence is reusable. Invalidate captures
             * before a later request can publish that sequence again. */
            c->input.sequence=0;
            --c->sequence;
            return 1;
        }
    }
    return 0;
}
static inline int md_entry_publish_response(struct md_entry_channel *c,unsigned state) {
    atomic_store_explicit(&c->state,state,memory_order_seq_cst);
    return atomic_load_explicit(&c->sleeping,memory_order_seq_cst)!=0;
}
static inline int md_entry_prepare_reply_wait(struct md_entry_channel *c,int native_sent,unsigned *expected) {
    atomic_store_explicit(&c->sleeping,1,memory_order_seq_cst);
    unsigned state=atomic_load_explicit(&c->state,memory_order_seq_cst);
    *expected=state;
    return state==MD_ENTRY_REQUEST || state==MD_ENTRY_RUNNING || state==MD_ENTRY_PARKED
        || (state==MD_ENTRY_NATIVE && native_sent);
}
enum { MD_ENTRY_PENDING_CALL=1, MD_ENTRY_PENDING_NATIVE=2 };
static inline unsigned md_entry_prepare_wait(struct md_entry_channel *c,enum md_entry_owner owner) {
    atomic_store_explicit(md_entry_owner_awake(c,owner),0,memory_order_seq_cst);
    unsigned pending=atomic_load_explicit(&c->state,memory_order_seq_cst)==MD_ENTRY_REQUEST
        && md_entry_request_owner(c->call.reserved)==owner ? MD_ENTRY_PENDING_CALL : 0;
    if (owner==MD_ENTRY_WORKER_OWNER) {
        unsigned state=atomic_load_explicit(&c->native.state,memory_order_seq_cst);
        if (md_native_resolved(state)) pending|=MD_ENTRY_PENDING_NATIVE;
    }
    return pending;
}
static inline int md_entry_early_native_result(struct md_entry_channel *c,long *result) {
    if (c->native_commit || atomic_load_explicit(&c->native.state,memory_order_acquire)!=MD_NATIVE_DONE)
        return 0;
    long value=c->native.result;
    unsigned offered=MD_ENTRY_NATIVE;
    if (!atomic_compare_exchange_strong_explicit(&c->state,&offered,MD_ENTRY_RETIRING,
            memory_order_seq_cst,memory_order_acquire)) return 0;
    *result=value;
    return 1;
}
/* The native-effect owner publishes receipts. A caller which claimed RETIRING already
 * owns the native result and may have queued its next request in call. */
static inline int md_entry_native_retire(struct md_entry_channel *c,uint64_t sequence,
        enum md_entry_outcome outcome,long result) {
    md_entry_record_reply(c,sequence,outcome,result);
    unsigned offered=MD_ENTRY_NATIVE;
    if (atomic_compare_exchange_strong_explicit(&c->state,&offered,MD_ENTRY_RESPONSE,
            memory_order_seq_cst,memory_order_acquire)) return 1;
    while (offered==MD_ENTRY_RETIRING || offered==MD_ENTRY_FD_RETIRING) {
        unsigned next=offered==MD_ENTRY_RETIRING ? MD_ENTRY_IDLE : MD_ENTRY_FD_REQUEST;
        if (atomic_compare_exchange_weak_explicit(&c->state,&offered,next,
                memory_order_release,memory_order_relaxed)) return 0;
    }
    if (offered!=MD_ENTRY_REQUEST) return -EPROTO;
    return 0;
}
#endif
