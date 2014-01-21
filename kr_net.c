#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#include "kr_net.h"

static void kr_net_set_error(char *err, const char *fmt, ...)
{
    va_list ap;

    if (!err) return;
    va_start(ap, fmt);
    vsnprintf(err, KR_NET_ERR_LEN, fmt, ap);
    va_end(ap);
}

int kr_net_nonblock(char *err, int fd)
{
    int flags;

    /* Set the socket nonblocking.
     * Note that fcntl(2) for F_GETFL and F_SETFL can't be
     * interrupted by a signal. */
    if ((flags = fcntl(fd, F_GETFL)) == -1) {
        kr_net_set_error(err, "fcntl(F_GETFL): %s", strerror(errno));
        return KR_NET_ERR;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        kr_net_set_error(err, "fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
        return KR_NET_ERR;
    }
    return KR_NET_OK;
}

int kr_net_tcp_nodelay(char *err, int fd)
{
    int yes = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) == -1)
    {
        kr_net_set_error(err, "setsockopt TCP_NODELAY: %s", strerror(errno));
        return KR_NET_ERR;
    }
    return KR_NET_OK;
}

int anetSetSendBuffer(char *err, int fd, int buffsize)
{
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffsize, sizeof(buffsize)) == -1)
    {
        kr_net_set_error(err, "setsockopt SO_SNDBUF: %s", strerror(errno));
        return KR_NET_ERR;
    }
    return KR_NET_OK;
}

int kr_net_tcp_keepalive(char *err, int fd)
{
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) == -1) {
        kr_net_set_error(err, "setsockopt SO_KEEPALIVE: %s", strerror(errno));
        return KR_NET_ERR;
    }
    return KR_NET_OK;
}

int kr_net_resolve(char *err, char *host, char *ipbuf)
{
    struct sockaddr_in sa;

    sa.sin_family = AF_INET;
    if (inet_aton(host, &sa.sin_addr) == 0) {
        struct hostent *he;

        he = gethostbyname(host);
        if (he == NULL) {
            kr_net_set_error(err, "can't resolve: %s", host);
            return KR_NET_ERR;
        }
        memcpy(&sa.sin_addr, he->h_addr, sizeof(struct in_addr));
    }
    strcpy(ipbuf,inet_ntoa(sa.sin_addr));
    return KR_NET_OK;
}

static int anetCreateSocket(char *err, int domain) {
    int s, on = 1;
    if ((s = socket(domain, SOCK_STREAM, 0)) == -1) {
        kr_net_set_error(err, "creating socket: %s", strerror(errno));
        return KR_NET_ERR;
    }

    /* Make sure connection-intensive things like the redis benckmark
     * will be able to close/open sockets a zillion of times */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
        kr_net_set_error(err, "setsockopt SO_REUSEADDR: %s", strerror(errno));
        return KR_NET_ERR;
    }
    return s;
}

#define KR_NET_CONNECT_NONE 0
#define KR_NET_CONNECT_NONBLOCK 1
static int anetTcpGenericConnect(char *err, char *addr, int port, int flags)
{
    int s;
    struct sockaddr_in sa;

    if ((s = anetCreateSocket(err,AF_INET)) == KR_NET_ERR)
        return KR_NET_ERR;

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_aton(addr, &sa.sin_addr) == 0) {
        struct hostent *he;

        he = gethostbyname(addr);
        if (he == NULL) {
            kr_net_set_error(err, "can't resolve: %s", addr);
            close(s);
            return KR_NET_ERR;
        }
        memcpy(&sa.sin_addr, he->h_addr, sizeof(struct in_addr));
    }
    if (flags & KR_NET_CONNECT_NONBLOCK) {
        if (kr_net_nonblock(err,s) != KR_NET_OK)
            return KR_NET_ERR;
    }
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        if (errno == EINPROGRESS &&
            flags & KR_NET_CONNECT_NONBLOCK)
            return s;

        kr_net_set_error(err, "connect: %s", strerror(errno));
        close(s);
        return KR_NET_ERR;
    }
    return s;
}

int kr_net_tcp_connect(char *err, char *addr, int port)
{
    return anetTcpGenericConnect(err,addr,port,KR_NET_CONNECT_NONE);
}

int kr_net_tcp_nonblock_connect(char *err, char *addr, int port)
{
    return anetTcpGenericConnect(err,addr,port,KR_NET_CONNECT_NONBLOCK);
}

int anetUnixGenericConnect(char *err, char *path, int flags)
{
    int s;
    struct sockaddr_un sa;

    if ((s = anetCreateSocket(err,AF_LOCAL)) == KR_NET_ERR)
        return KR_NET_ERR;

    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path,path,sizeof(sa.sun_path)-1);
    if (flags & KR_NET_CONNECT_NONBLOCK) {
        if (kr_net_nonblock(err,s) != KR_NET_OK)
            return KR_NET_ERR;
    }
    if (connect(s,(struct sockaddr*)&sa,sizeof(sa)) == -1) {
        if (errno == EINPROGRESS &&
            flags & KR_NET_CONNECT_NONBLOCK)
            return s;

        kr_net_set_error(err, "connect: %s", strerror(errno));
        close(s);
        return KR_NET_ERR;
    }
    return s;
}

int kr_net_unix_connect(char *err, char *path)
{
    return anetUnixGenericConnect(err,path,KR_NET_CONNECT_NONE);
}

int kr_net_unix_nonblock_connect(char *err, char *path)
{
    return anetUnixGenericConnect(err,path,KR_NET_CONNECT_NONBLOCK);
}

/* Like read(2) but make sure 'count' is read before to return
 * (unless error or EOF condition is encountered) */
int kr_net_read(int fd, char *buf, int count)
{
    int nread, totlen = 0;
    while(totlen != count) {
        nread = read(fd,buf,count-totlen);
        if (nread == 0) return totlen;
        if (nread == -1) {
            if (errno == EAGAIN || errno == EINTR) 
                continue;
            return -1;
        }
        totlen += nread;
        buf += nread;
    }
    return totlen;
}

/* Like write(2) but make sure 'count' is read before to return
 * (unless error is encountered) */
int kr_net_write(int fd, char *buf, int count)
{
    int nwritten, totlen = 0;
    while(totlen != count) {
        nwritten = write(fd,buf,count-totlen);
        if (nwritten == 0) return totlen;
        if (nwritten == -1) {
            if (errno == EAGAIN || errno == EINTR) 
                continue;
            return -1;
        }
        totlen += nwritten;
        buf += nwritten;
    }
    return totlen;
}

static int anetListen(char *err, int s, struct sockaddr *sa, socklen_t len) {
    if (bind(s,sa,len) == -1) {
        kr_net_set_error(err, "bind: %s", strerror(errno));
        close(s);
        return KR_NET_ERR;
    }

    /* Use a backlog of 512 entries. We pass 511 to the listen() call because
     * the kernel does: backlogsize = roundup_pow_of_two(backlogsize + 1);
     * which will thus give us a backlog of 512 entries */
    if (listen(s, 511) == -1) {
        kr_net_set_error(err, "listen: %s", strerror(errno));
        close(s);
        return KR_NET_ERR;
    }
    return KR_NET_OK;
}

int kr_net_tcp_server(char *err, int port, char *bindaddr)
{
    int s;
    struct sockaddr_in sa;

    if ((s = anetCreateSocket(err,AF_INET)) == KR_NET_ERR)
        return KR_NET_ERR;

    memset(&sa,0,sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bindaddr && inet_aton(bindaddr, &sa.sin_addr) == 0) {
        kr_net_set_error(err, "invalid bind address");
        close(s);
        return KR_NET_ERR;
    }
    if (anetListen(err,s,(struct sockaddr*)&sa,sizeof(sa)) == KR_NET_ERR)
        return KR_NET_ERR;
    return s;
}

int kr_net_unix_server(char *err, char *path, int perm)
{
    int s;
    struct sockaddr_un sa;

    if ((s = anetCreateSocket(err,AF_LOCAL)) == KR_NET_ERR)
        return KR_NET_ERR;

    memset(&sa,0,sizeof(sa));
    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path,path,sizeof(sa.sun_path)-1);
    if (anetListen(err,s,(struct sockaddr*)&sa,sizeof(sa)) == KR_NET_ERR)
        return KR_NET_ERR;
    if (perm)
        chmod(sa.sun_path, (mode_t)perm);
    return s;
}

static int anetGenericAccept(char *err, int s, struct sockaddr *sa, socklen_t *len) {
    int fd;
    while(1) {
        fd = accept(s,sa,len);
        if (fd == -1) {
            if (errno == EINTR)
                continue;
            else {
                kr_net_set_error(err, "accept: %s", strerror(errno));
                return KR_NET_ERR;
            }
        }
        break;
    }
    return fd;
}

int kr_net_tcp_accept(char *err, int s, char *ip, int *port) {
    int fd;
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    if ((fd = anetGenericAccept(err,s,(struct sockaddr*)&sa,&salen)) == KR_NET_ERR)
        return KR_NET_ERR;

    if (ip) strcpy(ip,inet_ntoa(sa.sin_addr));
    if (port) *port = ntohs(sa.sin_port);
    return fd;
}

int kr_net_unix_accept(char *err, int s) {
    int fd;
    struct sockaddr_un sa;
    socklen_t salen = sizeof(sa);
    if ((fd = anetGenericAccept(err,s,(struct sockaddr*)&sa,&salen)) == KR_NET_ERR)
        return KR_NET_ERR;

    return fd;
}

int kr_net_peer_to_string(int fd, char *ip, int *port) {
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);

    if (getpeername(fd,(struct sockaddr*)&sa,&salen) == -1) {
        *port = 0;
        ip[0] = '?';
        ip[1] = '\0';
        return -1;
    }
    if (ip) strcpy(ip,inet_ntoa(sa.sin_addr));
    if (port) *port = ntohs(sa.sin_port);
    return 0;
}
