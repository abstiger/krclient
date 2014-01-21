#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "kr_message.h"
#include "kr_alloc.h"
#include "kr_net.h"


static int kr_message_head_parse(char *msghead, T_KRMessage *krmsg)
{
    /* parse message header */
    char buff[KR_MSGHEADER_LEN+1];
    char *p = msghead;

    memset(buff, 0, sizeof(buff));
    memcpy(buff, p, KR_MSGTYPE_LEN); 
    p = p + KR_MSGTYPE_LEN;
    krmsg->msgtype = atoi(buff);

    memcpy(krmsg->msgid, p, KR_MSGID_LEN); 
    p = p + KR_MSGID_LEN;
    
    memcpy(krmsg->serverid, p, KR_SERVERID_LEN); 
    p = p + KR_SERVERID_LEN;

    memcpy(krmsg->clientid, p, KR_CLIENTID_LEN); 
    p = p + KR_CLIENTID_LEN;

    memset(buff, 0, sizeof(buff));
    memcpy(buff, p, KR_DATASRC_LEN); 
    p = p + KR_DATASRC_LEN;
    krmsg->datasrc = atoi(buff);

    memset(buff, 0, sizeof(buff));
    memcpy(buff, p, KR_MSGLEN_LEN); 
    p = p + KR_MSGLEN_LEN;
    krmsg->msglen = atoi(buff);

    return 0;
}


static int kr_message_head_dump(T_KRMessage *krmsg, char *msghead)
{
    if (krmsg->msgid[0] == '\0') krmsg->msgid[0] = '-';
    if (krmsg->serverid[0] == '\0') krmsg->serverid[0] = '-';
    if (krmsg->clientid[0] == '\0') krmsg->clientid[0] = '-';
    
    /* dump message header */
    sprintf(msghead, KR_MSGHEADER_FMT, \
        krmsg->msgtype, krmsg->msgid, krmsg->serverid, krmsg->clientid, \
        krmsg->datasrc, krmsg->msglen);

    return 0;
}


T_KRMessage *kr_message_alloc(void)
{
    /*need calloc here*/
    T_KRMessage *krmsg = kr_calloc(sizeof(*krmsg));
    return krmsg;
}


void kr_message_free(T_KRMessage *krmsg)
{
    if (krmsg) {
        if (krmsg->msgbuf) kr_free(krmsg->msgbuf);
        kr_free(krmsg); 
    }
}


T_KRMessage *kr_message_read(int fd)
{
    int readLen = 0;
    char msghead[KR_MSGHEADER_LEN+1] = {0};

    /* read message head */
    readLen = kr_net_read(fd, msghead, KR_MSGHEADER_LEN);
    if (readLen <= 0) {
        return NULL;
    } else if (readLen == 0) {
        return NULL;
    }
    
    /*alloc message*/
    T_KRMessage *krmsg = kr_message_alloc();
    if (krmsg == NULL) {
        return NULL;
    }
    krmsg->fd = fd;

    /* parse message head */
    if (kr_message_head_parse(msghead, krmsg) != 0) {
        kr_message_free(krmsg);
        return NULL;
    }

    /* read message body */
    if (readLen == KR_MSGHEADER_LEN && krmsg->msglen > 0) {
        krmsg->msgbuf = kr_malloc(krmsg->msglen);
        if (krmsg->msgbuf == NULL) {
            kr_message_free(krmsg);
            return NULL;
        }
        readLen = kr_net_read(fd, krmsg->msgbuf, krmsg->msglen);
        if (readLen != krmsg->msglen) {
            kr_message_free(krmsg);
            return NULL;
        }
    }

    return krmsg;
}


int kr_message_write(int fd, T_KRMessage *krmsg)
{
    int writeLen = 0;
    char msghead[KR_MSGHEADER_LEN+1] = {0};

    /* dump message head */
    if (kr_message_head_dump(krmsg, msghead) != 0) {
        return -1;
    }

    /* write message head */
    writeLen = kr_net_write(fd, msghead, KR_MSGHEADER_LEN);
    if (writeLen < 0) {
        return -1;
    } else if (writeLen == 0) {
        return 0;
    }

    /* write message body */
    if (writeLen == KR_MSGHEADER_LEN && krmsg->msglen > 0) {
        writeLen = kr_net_write(fd, krmsg->msgbuf, krmsg->msglen);
        if (writeLen != krmsg->msglen) {
            return -1;
        }
    }

    return writeLen;
}

