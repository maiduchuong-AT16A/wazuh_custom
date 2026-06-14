#include "local_writer.h"
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cJSON.h>

void write_local_alert(const RuleInfo *rule, const char *log_msg, const char *location) {
    char timestamp[64];
    time_t now = time(NULL);
    struct tm num_time;
    localtime_r(&now, &num_time);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", &num_time);

    cJSON *root = cJSON_CreateObject();
    if (!root) return;

    cJSON_AddStringToObject(root, "timestamp", timestamp);

    cJSON *rule_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(rule_json, "id", rule->sigid);
    cJSON_AddNumberToObject(rule_json, "level", rule->level);
    cJSON_AddStringToObject(rule_json, "description", rule->comment ? rule->comment : "");
    cJSON_AddItemToObject(root, "rule", rule_json);

    cJSON_AddStringToObject(root, "location", location ? location : "unknown");
    cJSON_AddStringToObject(root, "full_log", log_msg);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json_str) {
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
