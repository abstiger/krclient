#ifndef __KR_CLIENT_H__
#define __KR_CLIENT_H__

#include "kr_message.h"

typedef struct _kr_client_t {
    char         *id;
    char         *ip;
    int           port;
    int           fd;
    char          errmsg[1024];
}T_KRClient;

/*krclient*/
T_KRClient *kr_client_connect(char *ip, int port);
void kr_client_disconnect(T_KRClient *krclient);
int kr_client_set_timeout(T_KRClient *krclient, int secs);

T_KRMessage *kr_client_apply(T_KRClient *krclient, T_KRMessage *apply);
int kr_client_apply_file(T_KRClient *krclient, int msgtype, int datasrc, char *applyfile);

#endif /* __KR_CLIENT_H__ */
