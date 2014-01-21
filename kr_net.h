#ifndef __KR_NET_H__
#define __KR_NET_H__

#define KR_NET_OK 0
#define KR_NET_ERR -1
#define KR_NET_ERR_LEN 256

#if defined(__sun)
#define AF_LOCAL AF_UNIX
#endif

int kr_net_tcp_connect(char *err, char *addr, int port);
int kr_net_tcp_nonblock_connect(char *err, char *addr, int port);
int kr_net_unix_connect(char *err, char *path);
int kr_net_unix_nonblock_connect(char *err, char *path);
int kr_net_read(int fd, char *buf, int count);
int kr_net_resolve(char *err, char *host, char *ipbuf);
int kr_net_tcp_server(char *err, int port, char *bindaddr);
int kr_net_unix_server(char *err, char *path, int perm);
int kr_net_tcp_accept(char *err, int serversock, char *ip, int *port);
int kr_net_unix_accept(char *err, int serversock);
int kr_net_write(int fd, char *buf, int count);
int kr_net_nonblock(char *err, int fd);
int kr_net_tcp_nodelay(char *err, int fd);
int kr_net_tcp_keepalive(char *err, int fd);
int kr_net_peer_to_string(int fd, char *ip, int *port);

#endif /* __KR_NET_H__ */
