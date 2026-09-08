#include "local_writer.h"
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cJSON.h>

#include <unistd.h>
#include "os_net/os_net.h"
#include "defs.h"

static int alerts_sock = -1;

void write_local_alert(const RuleInfo *rule, const char *log_msg, const char *location) {
    char timestamp[64];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm num_time;
    localtime_r(&tv.tv_sec, &num_time);
    char tz[16];
    strftime(tz, sizeof(tz), "%z", &num_time);
    char dt[32];
    strftime(dt, sizeof(dt), "%Y-%m-%dT%H:%M:%S", &num_time);
    snprintf(timestamp, sizeof(timestamp), "%s.%03ld%s", dt, tv.tv_usec / 1000, tz);

    cJSON *root = cJSON_CreateObject();
    if (!root) return;

    cJSON_AddStringToObject(root, "timestamp", timestamp);

    cJSON *rule_json = cJSON_CreateObject();
    char sigid_str[16];
    snprintf(sigid_str, sizeof(sigid_str), "%d", rule->sigid);
    cJSON_AddStringToObject(rule_json, "id", sigid_str);
    cJSON_AddNumberToObject(rule_json, "level", rule->level);
    cJSON_AddStringToObject(rule_json, "description", rule->comment ? rule->comment : "");
    cJSON_AddNumberToObject(rule_json, "firedtimes", 1);
    cJSON_AddItemToObject(rule_json, "mail", cJSON_CreateBool(false));

    cJSON *groups = cJSON_CreateArray();
    if (rule->group && *rule->group) {
        char *grp_copy = strdup(rule->group);
        if (grp_copy) {
            char *saveptr = NULL;
            char *tok = strtok_r(grp_copy, ",", &saveptr);
            while (tok) {
                while (*tok == ' ') tok++;
                if (*tok) {
                    cJSON_AddItemToArray(groups, cJSON_CreateString(tok));
                }
                tok = strtok_r(NULL, ",", &saveptr);
            }
            free(grp_copy);
        }
    } else {
        cJSON_AddItemToArray(groups, cJSON_CreateString("ossec"));
    }
    cJSON_AddItemToObject(rule_json, "groups", groups);
    cJSON_AddItemToObject(root, "rule", rule_json);

    cJSON *decoder = cJSON_CreateObject();
    cJSON_AddStringToObject(decoder, "name", (location && *location) ? location : "ossec");
    cJSON_AddItemToObject(root, "decoder", decoder);

    cJSON_AddStringToObject(root, "location", location ? location : "unknown");
    cJSON_AddStringToObject(root, "full_log", log_msg);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json_str) {
        /* Forward JSON to Wazuh Manager via wazuh-agentd socket */
        if (alerts_sock < 0) {
            alerts_sock = OS_ConnectUnixDomain(ALERTSQUEUE, SOCK_DGRAM, OS_MAXSTR);
        }
        
        if (alerts_sock >= 0) {
            char fwd_msg[OS_MAXSTR + 1];
            snprintf(fwd_msg, OS_MAXSTR, "A:%s", json_str);
            if (OS_SendUnix(alerts_sock, fwd_msg, 0) < 0) {
                mdebug1("local-analysisd: Error sending alert to %s", ALERTSQUEUE);
                close(alerts_sock);
                alerts_sock = -1;
            } else {
                mdebug2("local-analysisd: Successfully forwarded alert to %s", ALERTSQUEUE);
            }
        } else {
            mdebug1("local-analysisd: Unable to connect to %s", ALERTSQUEUE);
        }

        /* Ensure directory exists */
        mkdir("logs", 0770);
        mkdir("logs/alerts", 0770);

        FILE *fp = fopen("logs/alerts/local_alerts.json", "a");
        if (fp) {
            fprintf(fp, "%s\n", json_str);
            fclose(fp);
        } else {
            mdebug1("local-analysisd: Cannot write to logs/alerts/local_alerts.json. Errno: %d (%s)", errno, strerror(errno));
        }

        /* Also print alert to log */
        minfo("local-analysisd: [ALERT] Rule %d (level %d): %s", rule->sigid, rule->level, rule->comment ? rule->comment : "");

        free(json_str);
    }
}
