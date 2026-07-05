#ifndef LOCAL_EXEC_H
#define LOCAL_EXEC_H

#include "shared.h"
#include "local_eventinfo.h"
#include "local_rules_engine.h"
#include "config/active-response.h"

/* Builds JSON payload and sends to wazuh-execd via EXECQUEUE socket */
void local_OS_Exec(active_response *ar, Eventinfo *lf, const RuleInfo *matched_rule, const char *raw_msg);

#endif /* LOCAL_EXEC_H */
