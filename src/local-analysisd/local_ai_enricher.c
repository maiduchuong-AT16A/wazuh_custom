#include "local_ai_enricher.h"
#include "local_writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cJSON.h>

int ai_confidence_to_level(double confidence) {
    if (confidence >= 0.90) return 12;
    if (confidence >= 0.80) return 10;
    if (confidence >= 0.70) return 8;
    if (confidence >= 0.60) return 6;
    if (confidence >= 0.50) return 5;
    return 3;
}

int ai_send_inference_request(const char *event_id, const char *os_type, const char *location, const char *log_content, ai_inference_response_t *resp) {
    if (!resp) return -1;
    memset(resp, 0, sizeof(ai_inference_response_t));

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        mdebug2("local_ai_enricher: Failed to create AF_UNIX socket: %s", strerror(errno));
        return -1;
    }

    /* Set socket non-blocking */
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        mdebug2("local_ai_enricher: Failed to set non-blocking flag: %s", strerror(errno));
        close(sock);
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, AI_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    int rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0) {
        if (errno == EINPROGRESS) {
            struct pollfd pfd;
            pfd.fd = sock;
            pfd.events = POLLOUT;
            int pret = poll(&pfd, 1, AI_TIMEOUT_MS);
            if (pret <= 0) {
                mdebug2("local_ai_enricher: Connect timeout (%d ms) to %s", AI_TIMEOUT_MS, AI_SOCKET_PATH);
                close(sock);
                return -1;
            }
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
                mdebug2("local_ai_enricher: Connect error to %s: %s", AI_SOCKET_PATH, strerror(so_error ? so_error : errno));
                close(sock);
                return -1;
            }
        } else {
            mdebug2("local_ai_enricher: Connect failed to %s: %s", AI_SOCKET_PATH, strerror(errno));
            close(sock);
            return -1;
        }
    }

    /* Format JSON request */
    char truncated_log[AI_MAX_LOG_SIZE + 1];
    if (log_content) {
        strncpy(truncated_log, log_content, AI_MAX_LOG_SIZE);
        truncated_log[AI_MAX_LOG_SIZE] = '\0';
    } else {
        truncated_log[0] = '\0';
    }

    cJSON *req_obj = cJSON_CreateObject();
    if (!req_obj) {
        close(sock);
        return -1;
    }
    cJSON_AddStringToObject(req_obj, "event_id", event_id ? event_id : "");
    cJSON_AddStringToObject(req_obj, "os_type", os_type ? os_type : "Linux");
    cJSON_AddStringToObject(req_obj, "location", location ? location : "");
    cJSON_AddStringToObject(req_obj, "log_content", truncated_log);

    char *json_str = cJSON_PrintUnformatted(req_obj);
    cJSON_Delete(req_obj);
    if (!json_str) {
        close(sock);
        return -1;
    }

    char send_buf[AI_MAX_REQUEST_SIZE + 2];
    int send_len = snprintf(send_buf, sizeof(send_buf), "%s\n", json_str);
    free(json_str);

    if (send_len <= 0 || send_len >= (int)sizeof(send_buf)) {
        mdebug2("local_ai_enricher: Payload exceeds buffer size");
        close(sock);
        return -1;
    }

    /* Send payload with poll timeout */
    struct pollfd pfd_out;
    pfd_out.fd = sock;
    pfd_out.events = POLLOUT;
    if (poll(&pfd_out, 1, AI_TIMEOUT_MS) <= 0) {
        mdebug2("local_ai_enricher: Send poll timeout");
        close(sock);
        return -1;
    }

    ssize_t sent = send(sock, send_buf, send_len, 0);
    if (sent < send_len) {
        mdebug2("local_ai_enricher: Incomplete send (%zd/%d bytes)", sent, send_len);
        close(sock);
        return -1;
    }

    /* Receive response with poll timeout */
    char recv_buf[AI_MAX_REQUEST_SIZE + 1];
    int total_recv = 0;
    while (total_recv < (int)sizeof(recv_buf) - 1) {
        struct pollfd pfd_in;
        pfd_in.fd = sock;
        pfd_in.events = POLLIN;
        int pret = poll(&pfd_in, 1, AI_TIMEOUT_MS);
        if (pret <= 0) {
            mdebug2("local_ai_enricher: Recv poll timeout (%d ms)", AI_TIMEOUT_MS);
            close(sock);
            return -1;
        }

        ssize_t n = recv(sock, recv_buf + total_recv, sizeof(recv_buf) - 1 - total_recv, 0);
        if (n <= 0) {
            break;
        }
        total_recv += n;
        recv_buf[total_recv] = '\0';
        if (strchr(recv_buf, '\n')) {
            break;
        }
    }

    close(sock);

    if (total_recv <= 0) {
        mdebug2("local_ai_enricher: Empty response received");
        return -1;
    }

    /* Parse JSON response */
    cJSON *resp_obj = cJSON_Parse(recv_buf);
    if (!resp_obj) {
        mdebug2("local_ai_enricher: Failed to parse JSON response: %s", recv_buf);
        return -1;
    }

    cJSON *eid = cJSON_GetObjectItem(resp_obj, "event_id");
    if (eid && eid->valuestring) {
        strncpy(resp->event_id, eid->valuestring, sizeof(resp->event_id) - 1);
    }

    cJSON *malicious = cJSON_GetObjectItem(resp_obj, "is_malicious");
    if (malicious) {
        resp->is_malicious = cJSON_IsTrue(malicious);
    }

    cJSON *att = cJSON_GetObjectItem(resp_obj, "attack_type");
    if (att && att->valuestring) {
        strncpy(resp->attack_type, att->valuestring, sizeof(resp->attack_type) - 1);
    }

    cJSON *conf = cJSON_GetObjectItem(resp_obj, "confidence_score");
    if (conf && cJSON_IsNumber(conf)) {
        resp->confidence_score = conf->valuedouble;
    }

    cJSON *err = cJSON_GetObjectItem(resp_obj, "error");
    if (err && err->valuestring) {
        strncpy(resp->error, err->valuestring, sizeof(resp->error) - 1);
    }

    cJSON_Delete(resp_obj);
    return 0;
}

void ai_generate_alert(const ai_inference_response_t *resp, const Eventinfo *lf, const char *raw_msg) {
    if (!resp || !resp->is_malicious) return;

    RuleInfo ai_rule;
    memset(&ai_rule, 0, sizeof(RuleInfo));
    ai_rule.sigid = AI_RULE_ID;
    ai_rule.level = ai_confidence_to_level(resp->confidence_score);

    char comment_buf[256];
    snprintf(comment_buf, sizeof(comment_buf), "AI Threat Detected: %s (Confidence: %.2f%%)",
             resp->attack_type[0] ? resp->attack_type : "Unknown Threat",
             resp->confidence_score * 100.0);
    ai_rule.comment = comment_buf;
    ai_rule.group = "ai_detection,attack";

    const char *log_text = (lf && lf->full_log) ? lf->full_log : raw_msg;
    const char *location = (lf && lf->location) ? lf->location : "ai_engine";

    minfo("wazuh-local-analysisd: [AI-ALERT] Threat detected: %s with confidence %.2f%% (Level %d)",
          resp->attack_type, resp->confidence_score * 100.0, ai_rule.level);

    write_local_alert(&ai_rule, log_text, location);
}

int local_ai_enrich_event(Eventinfo *lf, const char *raw_msg) {
    const char *log_content = (lf && lf->full_log) ? lf->full_log : raw_msg;
    if (!log_content || !*log_content) {
        return 0;
    }

    /* Determine OS type based on log characteristics */
    const char *os_type = "Linux";
    const char *loc = (lf && lf->location) ? lf->location : "";
    if (strstr(loc, "WinEvtLog") || strstr(loc, "Security") || strstr(loc, "System") ||
        strstr(log_content, "Microsoft-Windows") || strstr(log_content, "Sysmon") ||
        strstr(log_content, "EventID")) {
        os_type = "Windows";
    }

    char event_id[64];
    static unsigned long counter = 0;
    snprintf(event_id, sizeof(event_id), "ai-evt-%ld-%lu", (long)time(NULL), ++counter);

    ai_inference_response_t resp;
    int rc = ai_send_inference_request(event_id, os_type, loc, log_content, &resp);
    if (rc != 0) {
        /* Fallback: daemon not running or timeout -> skip silently without crashing */
        return 0;
    }

    if (resp.is_malicious && resp.confidence_score >= AI_CONFIDENCE_THRESHOLD) {
        ai_generate_alert(&resp, lf, raw_msg);
        return 1;
    }

    return 0;
}
