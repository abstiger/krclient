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
    sscanf(msghead, KR_MSGHEADER_FMT, \
        &krmsg->msgtype, krmsg->msgid, krmsg->serverid, krmsg->clientid, \
        &krmsg->datasrc, krmsg->objectkey, &krmsg->msglen);

    if (krmsg->msgid[0] == '-') krmsg->msgid[0] = '\0';
    if (krmsg->serverid[0] == '-') krmsg->serverid[0] = '\0';
    if (krmsg->clientid[0] == '-') krmsg->clientid[0] = '\0';
    if (krmsg->objectkey[0] == '-') krmsg->objectkey[0] = '\0';

    return 0;
}


static int kr_message_head_dump(T_KRMessage *krmsg, char *msghead)
{
    if (krmsg->msgid[0] == '\0') krmsg->msgid[0] = '-';
    if (krmsg->serverid[0] == '\0') krmsg->serverid[0] = '-';
    if (krmsg->clientid[0] == '\0') krmsg->clientid[0] = '-';
    if (krmsg->objectkey[0] == '\0') krmsg->objectkey[0] = '-';
    
    /* dump message header */
    sprintf(msghead, KR_MSGHEADER_FMT, \
        krmsg->msgtype, krmsg->msgid, krmsg->serverid, krmsg->clientid, \
        krmsg->datasrc, krmsg->objectkey, krmsg->msglen);

    return 0;
}


T_KRMessage *kr_message_alloc(void)
{
    T_KRMessage *krmsg = kr_calloc(sizeof(*krmsg));
    if (krmsg == NULL) {
        return NULL;
    }

    return krmsg;
}


void kr_message_free(T_KRMessage *krmsg)
{
    if (krmsg) {
        if (krmsg->msgbuf) kr_free(krmsg->msgbuf);
        kr_free(krmsg); krmsg = NULL;
    }
}


int kr_message_read(int fd, T_KRMessage *krmsg)
{
    int readLen = 0;
    char msghead[KR_MSGHEADER_LEN+1] = {0};

    krmsg->fd = fd;
    /* read message head */
    readLen = kr_net_read(fd, msghead, KR_MSGHEADER_LEN);
    if (readLen <= 0) {
        return -1;
    } else if (readLen == 0) {
        return 0;
    }
    
    /* parse message head */
    if (kr_message_head_parse(msghead, krmsg) != 0) {
        return -1;
    }

    /* read message body */
    if (readLen == KR_MSGHEADER_LEN && krmsg->msglen > 0) {
        krmsg->msgbuf = kr_malloc(krmsg->msglen);
        if (krmsg->msgbuf == NULL) {
            return -1;
        }
        readLen = kr_net_read(fd, krmsg->msgbuf, krmsg->msglen);
        if (readLen != krmsg->msglen) {
            kr_free(krmsg->msgbuf);
            return -1;
        }
    }

    return readLen;
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

