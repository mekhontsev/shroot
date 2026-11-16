#if defined(AUDIT_const)
extern int external;
int *const relocated_constant[]={&external};
__attribute__((weak)) const int weak_constant=1;
_Thread_local void *md_lwip_current;
#elif defined(AUDIT_mutable)
int mutable_state=1;
#elif defined(AUDIT_weak)
__attribute__((weak)) int weak_state;
#elif defined(AUDIT_tls)
_Thread_local int unrelated_tls;
#elif defined(AUDIT_current)
void *md_lwip_current;
#endif
