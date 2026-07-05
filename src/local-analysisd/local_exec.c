#include "local_exec.h"
#include "os_net/os_net.h"
#include <cJSON.h>
#include <time.h>

#define VERSION 1
#define ARGV0 "wazuh-local-analysisd"

static void local_getActiveResponseInJSON(const Eventinfo *lf, const active_response *ar, const RuleInfo *matched_rule, __attribute__((unused)) const char *raw_msg, char *temp_msg) {
    cJSON *_object = NULL;
    cJSON *_array = NULL;
    char *msg = NULL;
    cJSON *parameters = NULL;

    cJSON *message = cJSON_CreateObject();
    cJSON_AddNumberToObject(message, "version", VERSION);

    _object = cJSON_CreateObject();
    cJSON_AddItemToObject(message, "origin", _object);
    cJSON_AddStringToObject(_object, "name", "local-node");
    cJSON_AddStringToObject(_object, "module", ARGV0);

    char cmd_name[256];
    snprintf(cmd_name, sizeof(cmd_name), "%s%d", ar->ar_cmd->name, ar->timeout);
    cJSON_AddStringToObject(message, "command", cmd_name);

    parameters = cJSON_CreateObject();
    cJSON_AddItemToObject(message, "parameters", parameters);

    _array = cJSON_CreateArray();
    cJSON_AddItemToObject(parameters, "extra_args", _array);

    if (ar->ar_cmd->extra_args) {
        char str[OS_SIZE_2048];
        char *pch;
        strncpy(str, ar->ar_cmd->extra_args, OS_SIZE_2048 - 1);
        pch = strtok(str, " ");
        while (pch != NULL) {
            cJSON_AddItemToArray(_array, cJSON_CreateString(pch));
            pch = strtok(NULL, " ");
        }
    }

    /* Build Alert JSON */
    cJSON *json_alert = cJSON_CreateObject();
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm num_time;
    localtime_r(&now, &num_time);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", &num_time);
    cJSON_AddStringToObject(json_alert, "timestamp", timestamp);

    cJSON *rule_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(rule_json, "level", matched_rule->level);
    cJSON_AddStringToObject(rule_json, "description", matched_rule->comment ? matched_rule->comment : "");
    char rule_id_str[32];
    snprintf(rule_id_str, sizeof(rule_id_str), "%d", matched_rule->sigid);
    cJSON_AddStringToObject(rule_json, "id", rule_id_str);
    cJSON_AddNumberToObject(rule_json, "firedtimes", 1);
    cJSON_AddItemToObject(json_alert, "rule", rule_json);

    cJSON_AddStringToObject(json_alert, "location", lf->location ? lf->location : "unknown");

    /* Add data fields (srcip, dstuser, etc.) */
    cJSON *data_json = cJSON_CreateObject();
    int has_data = 0;
    if (lf->srcip) { cJSON_AddStringToObject(data_json, "srcip", lf->srcip); has_data = 1; }
    if (lf->dstip) { cJSON_AddStringToObject(data_json, "dstip", lf->dstip); has_data = 1; }
    if (lf->dstuser) { cJSON_AddStringToObject(data_json, "dstuser", lf->dstuser); has_data = 1; }
    if (lf->srcuser) { cJSON_AddStringToObject(data_json, "srcuser", lf->srcuser); has_data = 1; }
    
    if (has_data) {
        cJSON_AddItemToObject(json_alert, "data", data_json);
    } else {
        cJSON_Delete(data_json);
    }

    cJSON_AddItemToObject(parameters, "alert", json_alert);

    msg = cJSON_PrintUnformatted(message);
    cJSON_Delete(message);

    if (msg) {
        strncpy(temp_msg, msg, OS_MAXSTR);
        os_free(msg);
    } else {
        temp_msg[0] = '\0';
    }
}

static int execd_sock = -1;

void local_OS_Exec(active_response *ar, Eventinfo *lf, const RuleInfo *matched_rule, const char *raw_msg) {
    char msg[OS_MAXSTR + 1];
    msg[OS_MAXSTR] = '\0';

    local_getActiveResponseInJSON(lf, ar, matched_rule, raw_msg, msg);

    if (msg[0] != '\0') {
        if (execd_sock < 0) {
            execd_sock = OS_ConnectUnixDomain(EXECQUEUE, SOCK_DGRAM, OS_MAXSTR);
        }

        if (execd_sock >= 0) {
            if (OS_SendUnix(execd_sock, msg, 0) < 0) {
                merror("wazuh-local-analysisd: Error sending Active Response to %s", EXECQUEUE);
                close(execd_sock);
                execd_sock = -1;
            } else {
                minfo("wazuh-local-analysisd: Active response sent to execd: %s", msg);
            }
        } else {
            merror("wazuh-local-analysisd: Unable to connect to Active Response socket %s", EXECQUEUE);
        }
    }
}
