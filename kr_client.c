#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

#include "kr_alloc.h"
#include "kr_net.h"
#include "kr_json.h"
#include "kr_message.h"
#include "kr_client.h"


void kr_client_disconnect(T_KRClient *krclient)
{
    if (krclient) {
        if (krclient->id) kr_free(krclient->id);
        if (krclient->ip) kr_free(krclient->ip);
        if (krclient->fd) {
            close(krclient->fd);
            shutdown(krclient->fd, SHUT_RDWR);
        }
        kr_free(krclient);
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

    krclient->id = kr_strdup("krclient1");//FIXME
    krclient->ip = kr_strdup(ip);
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

T_KRMessage *kr_client_apply(T_KRClient *krclient, int msgtype, int datasrc, int msglen, void *msgbuf)
{
    /*alloc request*/
    T_KRMessage *apply = kr_message_alloc();
    if (apply == NULL) {
		fprintf(stderr, "kr_message_alloc request failed!\n");
		return NULL;
    }

    /*set request*/
    apply->msgtype = msgtype;
    apply->datasrc = datasrc;
    apply->msglen = msglen;
    apply->msgbuf = msgbuf;

    /*send request*/
    if (kr_message_write(krclient->fd, apply) <= 0) {
		fprintf(stderr, "kr_message_write request failed!\n");
        kr_message_free(apply);
		return NULL;
    }

    /*get response*/
    T_KRMessage *reply = kr_message_read(krclient->fd);
    if (reply == NULL) {
		fprintf(stderr, "kr_message_read response failed!\n");
        kr_message_free(apply);
		return NULL;
    }

    kr_message_free(apply);
    return reply;
}


T_KRMessage *kr_client_info(T_KRClient *krclient)
{
    return kr_client_apply(krclient, KR_MSGTYPE_INFO, 0, 0, NULL);
}

T_KRMessage *kr_client_info_log(T_KRClient *krclient)
{
    return kr_client_apply(krclient, KR_MSGTYPE_INFO_LOG, 0, 0, NULL);
}

T_KRMessage *kr_client_set_logpath(T_KRClient *krclient, char *log_path)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "log_path", log_path);
    char *msgbuf = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    return kr_client_apply(krclient, KR_MSGTYPE_SET_LOGPATH, 0, strlen(msgbuf), msgbuf);
}

T_KRMessage *kr_client_set_logname(T_KRClient *krclient, char *log_name)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "log_name", log_name);
    char *msgbuf = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    return kr_client_apply(krclient, KR_MSGTYPE_SET_LOGNAME, 0, strlen(msgbuf), msgbuf);
}

T_KRMessage *kr_client_set_loglevel(T_KRClient *krclient, int log_level)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "log_level", log_level);
    char *msgbuf = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    return kr_client_apply(krclient, KR_MSGTYPE_SET_LOGLEVEL, 0, strlen(msgbuf), msgbuf);
}

T_KRMessage *kr_client_info_krdb(T_KRClient *krclient)
{
    return kr_client_apply(krclient, KR_MSGTYPE_INFO_KRDB, 0, 0, NULL);
}

T_KRMessage *kr_client_info_table(T_KRClient *krclient, int table_id)
{
    return kr_client_apply(krclient, KR_MSGTYPE_INFO_TABLE, table_id, 0, NULL);
}

T_KRMessage *kr_client_info_index(T_KRClient *krclient, int table_id, int index_id)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "index_id", index_id);
    char *msgbuf = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    return kr_client_apply(krclient, KR_MSGTYPE_INFO_INDEX, table_id, strlen(msgbuf), msgbuf);
}

T_KRMessage *kr_client_list_index_key(T_KRClient *krclient)
{
    return kr_client_apply(krclient, KR_MSGTYPE_LIST_INDEX_KEY, 0, 0, NULL);
}

T_KRMessage *kr_client_reload_param(T_KRClient *krclient)
{
    return kr_client_apply(krclient, KR_MSGTYPE_RELOAD_PARAM, 0, 0, NULL);
}

T_KRMessage *kr_client_info_param(T_KRClient *krclient)
{
    return kr_client_apply(krclient, KR_MSGTYPE_INFO_PARAM, 0, 0, NULL);
}

T_KRMessage *kr_client_info_group(T_KRClient *krclient, int group_id)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "group_id", group_id);
    char *msgbuf = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    return kr_client_apply(krclient, KR_MSGTYPE_INFO_GROUP, 0, strlen(msgbuf), msgbuf);
}

T_KRMessage *kr_client_info_group_rule(T_KRClient *krclient, int group_id, int rule_id)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "group_id", group_id);
    cJSON_AddNumberToObject(json, "rule_id", rule_id);
    char *msgbuf = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    return kr_client_apply(krclient, KR_MSGTYPE_INFO_RULE, 0, strlen(msgbuf), msgbuf);
}

T_KRMessage *kr_client_info_set(T_KRClient *krclient, int set_id)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "set_id", set_id);
    char *msgbuf = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    return kr_client_apply(krclient, KR_MSGTYPE_INFO_SET, 0, strlen(msgbuf), msgbuf);
}

T_KRMessage *kr_client_info_sdi(T_KRClient *krclient, int sdi_id)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "sdi_id", sdi_id);
    char *msgbuf = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    return kr_client_apply(krclient, KR_MSGTYPE_INFO_SDI, 0, strlen(msgbuf), msgbuf);
}

T_KRMessage *kr_client_info_ddi(T_KRClient *krclient, int ddi_id)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "ddi_id", ddi_id);
    char *msgbuf = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    return kr_client_apply(krclient, KR_MSGTYPE_INFO_DDI, 0, strlen(msgbuf), msgbuf);
}

T_KRMessage *kr_client_info_hdi(T_KRClient *krclient, int hdi_id)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "hdi_id", hdi_id);
    char *msgbuf = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    return kr_client_apply(krclient, KR_MSGTYPE_INFO_HDI, 0, strlen(msgbuf), msgbuf);
}

T_KRMessage *kr_client_insert_event(T_KRClient *krclient, int table_id, char *event)
{
    char *msgbuf = strdup(event);
    return kr_client_apply(krclient, KR_MSGTYPE_INSERT_EVENT, table_id, strlen(msgbuf), msgbuf);
}

T_KRMessage *kr_client_detect_event(T_KRClient *krclient, int table_id, char *event)
{
    char *msgbuf = strdup(event);
    return kr_client_apply(krclient, KR_MSGTYPE_DETECT_EVENT, table_id, strlen(msgbuf), msgbuf);
}

static void kr_client_tick_time(char *memo)
{
    time_t tTime = time(NULL);
    struct tm *ptmNow = localtime(&tTime);
    char caTimeString[80] = {0};
    strftime(caTimeString, sizeof(caTimeString), "%c", ptmNow);
    printf("%s: time tick:[%s]!\n", memo, caTimeString);
}

int kr_client_apply_file(T_KRClient *krclient, int msgtype, int table_id, char *applyfile)
{
	int iCnt = 0;
    char buff[1024] = {0};

	FILE *fp = fopen(applyfile, "r");
	if (fp == NULL) {
		fprintf(stderr, "fopen applyfile [%s] failed!\n", applyfile);
		return -1;
    }

    kr_client_tick_time("start");
	while(fgets(buff, sizeof(buff), fp) != NULL)
	{
		if (buff[0] == ' ') continue;

        /*apply this line*/
        char *msgbuf = strdup(buff);
        T_KRMessage *reply = kr_client_apply(krclient, msgtype, table_id, strlen(msgbuf), msgbuf);
        if (reply == NULL) {
            fprintf(stderr, "kr_client_apply [%zu] [%s] failed!\n", 
                    strlen(msgbuf), msgbuf);
            return -1;
        }
        /*print reply*/
        if (reply->msgtype == KR_MSGTYPE_SUCCESS) {
            fprintf(stdout, "SUCCESS: %s\n", reply->msgbuf);
        } else {
            fprintf(stdout, "ERROR!\n");
        }

        if(iCnt%1000 == 0 && iCnt != 0) {
            char caNum[20] = {0};
            snprintf(caNum, sizeof(caNum), "Records:%010d", iCnt);
            kr_client_tick_time(caNum);
        }
		iCnt++;
    }
    kr_client_tick_time("stop");
    fclose(fp);

    return 0;
}

int kr_client_insert_file(T_KRClient *krclient, int table_id, char *applyfile)
{
    if (access(applyfile, R_OK) != 0) {
        fprintf(stderr, "file [%s] can not access!\n", applyfile);
        return -1;
    }

    return kr_client_apply_file(krclient, 
            KR_MSGTYPE_INSERT_EVENT, table_id, applyfile);
}

int kr_client_detect_file(T_KRClient *krclient, int table_id, char *applyfile)
{
    if (access(applyfile, R_OK) != 0) {
        fprintf(stderr, "file [%s] can not access!\n", applyfile);
        return -1;
    }

    return kr_client_apply_file(krclient, 
            KR_MSGTYPE_DETECT_EVENT, table_id, applyfile);
}

