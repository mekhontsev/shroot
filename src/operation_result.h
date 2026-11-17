#ifndef MD_OPERATION_RESULT_H
#define MD_OPERATION_RESULT_H
/* Internal continuation status, outside Linux's errno range. Never publish
 * it as a completed syscall result. Terminal EINPROGRESS remains an errno. */
enum { MD_OPERATION_PENDING = -4096 };
#endif
