#ifndef __KR_MESSAGE_H__
#define __KR_MESSAGE_H__

/* The message format for krproject communication:
 * |msgtype(4bytes)|msgid(16bytes)|serverid(26bytes)|clientid(26bytes)|datasrcid(4bytes)|msglen(4bytes)|message(msglen bytes)|
 */

#define KR_MSGTYPE_LEN 4
#define KR_MSGID_LEN 16
#define KR_SERVERID_LEN 26
#define KR_CLIENTID_LEN 26
#define KR_DATASRC_LEN 4
#define KR_MSGLEN_LEN 4

#define KR_MSGHEADER_LEN 80
#define KR_MSGHEADER_FMT "%4d%16s%26s%26s%4d%4d"


/*message type define*/
/*reply msgtype*/
#define    KR_MSGTYPE_ERROR            -1
#define    KR_MSGTYPE_SUCCESS           0

/*apply msgtype*/
/*krserver*/
#define    KR_MSGTYPE_SVRON             1
#define    KR_MSGTYPE_SVROFF            2
#define    KR_MSGTYPE_CLION             3
#define    KR_MSGTYPE_CLIOFF            4
#define    KR_MSGTYPE_HEART             5
#define    KR_MSGTYPE_INFO              10

/*krengine*/
#define    KR_MSGTYPE_INFO_LOG          20
#define    KR_MSGTYPE_SET_LOGPATH       21
#define    KR_MSGTYPE_SET_LOGNAME       22
#define    KR_MSGTYPE_SET_LOGLEVEL      23

/*krdb*/
#define    KR_MSGTYPE_INFO_KRDB         31
#define    KR_MSGTYPE_INFO_TABLE        32
#define    KR_MSGTYPE_INFO_INDEX        33
#define    KR_MSGTYPE_LIST_INDEX_KEY    34

/*krparam*/
#define    KR_MSGTYPE_RELOAD_PARAM      40
#define    KR_MSGTYPE_INFO_PARAM        41
#define    KR_MSGTYPE_INFO_GROUP        42
#define    KR_MSGTYPE_INFO_RULE         43
#define    KR_MSGTYPE_INFO_SET          44
#define    KR_MSGTYPE_INFO_SDI          45
#define    KR_MSGTYPE_INFO_DDI          46
#define    KR_MSGTYPE_INFO_HDI          47

#define    KR_MSGTYPE_INSERT_EVENT      50
#define    KR_MSGTYPE_DETECT_EVENT      60

typedef struct _kr_message_t
{
    int         fd;
    int         msgtype;
    char        msgid[KR_MSGID_LEN+1];
    char        serverid[KR_SERVERID_LEN+1];
    char        clientid[KR_CLIENTID_LEN+1];
    int         datasrc;
    int         msglen;
    char       *msgbuf;
}T_KRMessage;

typedef void (*KRCallBackFunc)(T_KRMessage *apply, T_KRMessage *reply, void *data);

T_KRMessage *kr_message_alloc(void);
void kr_message_free(T_KRMessage *krmsg);

T_KRMessage *kr_message_read(int fd);
int kr_message_write(int fd, T_KRMessage *krmsg);

#endif /* __KR_MESSAGE_H__ */
