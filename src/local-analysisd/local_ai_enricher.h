#ifndef LOCAL_AI_ENRICHER_H
#define LOCAL_AI_ENRICHER_H

#include "shared.h"
#include "local_rules_engine.h"
#include "local_eventinfo.h"

#define AI_SOCKET_PATH "/var/ossec/queue/ai/ai_inference.sock"
#define AI_TIMEOUT_MS 500
#define AI_MAX_REQUEST_SIZE 4096

#define AI_MAX_LOG_SIZE 2048
#define AI_RULE_ID 99999
#define AI_CONFIDENCE_THRESHOLD 0.50

typedef struct {
    char event_id[64];
    int is_malicious;
    char attack_type[128];
    double confidence_score;
    char error[256];
} ai_inference_response_t;

/* Function Declarations */
int local_ai_enrich_event(Eventinfo *lf, const char *raw_msg);
int ai_send_inference_request(const char *event_id, const char *os_type, const char *location, const char *log_content, ai_inference_response_t *resp);
void ai_generate_alert(const ai_inference_response_t *resp, const Eventinfo *lf, const char *raw_msg);
int ai_confidence_to_level(double confidence);

#endif /* LOCAL_AI_ENRICHER_H */
