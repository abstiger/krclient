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

T_KRMessage *kr_client_apply(T_KRClient *krclient, int msgtype, int datasrc, int msglen, void *msgbuf);
T_KRMessage *kr_client_info(T_KRClient *krclient);
T_KRMessage *kr_client_info_log(T_KRClient *krclient);
T_KRMessage *kr_client_set_logpath(T_KRClient *krclient, char *log_path);
T_KRMessage *kr_client_set_logname(T_KRClient *krclient, char *log_name);
T_KRMessage *kr_client_set_loglevel(T_KRClient *krclient, int log_level);
T_KRMessage *kr_client_info_krdb(T_KRClient *krclient);
T_KRMessage *kr_client_info_table(T_KRClient *krclient, int table_id);
T_KRMessage *kr_client_info_index(T_KRClient *krclient, int table_id, int index_id);
T_KRMessage *kr_client_list_index_key(T_KRClient *krclient);
T_KRMessage *kr_client_reload_param(T_KRClient *krclient);
T_KRMessage *kr_client_info_param(T_KRClient *krclient);
T_KRMessage *kr_client_info_group(T_KRClient *krclient, int group_id);
T_KRMessage *kr_client_info_group_rule(T_KRClient *krclient, int group_id, int rule_id);
T_KRMessage *kr_client_info_set(T_KRClient *krclient, int set_id);
T_KRMessage *kr_client_info_sdi(T_KRClient *krclient, int sdi_id);
T_KRMessage *kr_client_info_ddi(T_KRClient *krclient, int ddi_id);
T_KRMessage *kr_client_info_hdi(T_KRClient *krclient, int hdi_id);
T_KRMessage *kr_client_insert_event(T_KRClient *krclient, int table_id, char *event);
T_KRMessage *kr_client_detect_event(T_KRClient *krclient, int table_id, char *event);

int kr_client_apply_file(T_KRClient *krclient, int msgtype, int table_id, char *applyfile);
int kr_client_insert_file(T_KRClient *krclient, int table_id, char *applyfile);
int kr_client_detect_file(T_KRClient *krclient, int table_id, char *applyfile);

#endif /* __KR_CLIENT_H__ */
