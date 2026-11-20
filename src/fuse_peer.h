#ifndef MD_FUSE_PEER_H
#define MD_FUSE_PEER_H
struct md_fuse_connection;
struct md_fuse_peer;
/* Host AF_UNIX stream, FUSE requests and replies framed by their Linux
 * headers. @name denotes the abstract namespace. Never a guest pathname. */
int md_fuse_peer_start(const char *,struct md_fuse_connection *,struct md_fuse_peer **);
void md_fuse_peer_close(struct md_fuse_peer *);
#endif
