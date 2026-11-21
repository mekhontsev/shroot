#ifndef MD_NETWORK_LOOPBACK_H
#define MD_NETWORK_LOOPBACK_H
#include "network_ip.h"
#include <stdint.h>
struct md_network_fabric;
/* Called under the fabric lock. Names are private to the supervisor's leased directory. */
int md_loopback_bind(struct md_network_fabric *,int,uint64_t,struct md_inet_address);
void md_loopback_unbind(struct md_network_fabric *,uint64_t,struct md_inet_address);
int md_loopback_address(const struct md_network_fabric *,uint64_t,struct md_inet_address,
    struct sockaddr_storage *,socklen_t *);
int md_loopback_source(const struct md_network_fabric *,const struct sockaddr_storage *,socklen_t,
    struct md_inet_address *);
#endif
