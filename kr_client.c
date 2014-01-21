#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

#include "kr_net.h"
#include "kr_json.h"
#include "kr_message.h"
#include "kr_client.h"


void kr_client_disconnect(T_KRClient *krclient)
{
    if (krclient) {
        if (krclient->id) free(krclient->id);
        if (krclient->ip) free(krclient->ip);
        if (krclient->fd) {
            close(krclient->fd);
            shutdown(krclient->fd, SHUT_RDWR);
        }
        free(krclient);
    }
}

int kr_client_set_timeout(T_KRClient *krclient, int secs)
{
    struct timeval timeout = {secs, 0};

    if (setsockopt(krclient->fd, SOL_SOCKET, SO_RCVTIMEO, 
                (char *)&timeout, sizeof(struct timeval)) != 0) {
        fprintf(stderr, "setsockopt SO_RCVTIMEO failed![%s]", strerror(errno));
        return -1;
    }

    if (setsockopt(krclient->fd, SOL_SOCKET, SO_SNDTIMEO, 
                (char *)&timeout, sizeof(struct timeval)) != 0) {
        fprintf(stderr, "setsockopt SO_SNDTIMEO failed![%s]", strerror(errno));
        return -1;
    }

    return 0;
}

T_KRClient *kr_client_connect(char *ip, int port)
{
    T_KRClient *krclient = malloc(sizeof(*krclient));
    if (krclient == NULL) {
        fprintf(stderr, "malloc krclient failed!\n");
        return NULL;
    }

    krclient->id = strdup("krclient1");//FIXME
    krclient->ip = strdup(ip);
    krclient->port = port;
    krclient->fd = kr_net_tcp_connect(krclient->errmsg, 
            krclient->ip, krclient->port);
    if (krclient->fd <= 0) {
        fprintf(stderr, "connect server [%s:%d] failed[%s]\n",
                krclient->ip, krclient->port, krclient->errmsg);
        kr_client_disconnect(krclient);
        return NULL;
    }

    /*default timeout is 3 seconds*/
    if (kr_client_set_timeout(krclient, 3) != 0) {
        fprintf(stderr, "kr_client_set_timeout 3 failed!\n");
        kr_client_disconnect(krclient);
        return NULL;
    }

    return krclient;
}

T_KRMessage *kr_client_apply(T_KRClient *krclient, T_KRMessage *apply)
{
    /*send request*/
    if (kr_message_write(krclient->fd, apply) <= 0) {
		fprintf(stderr, "kr_message_write request failed!\n");
		return NULL;
    }

    /*get response*/
    T_KRMessage *reply = kr_message_read(krclient->fd);
    if (reply == NULL) {
		fprintf(stderr, "kr_message_read response failed!\n");
		return NULL;
    }

    return reply;
}
