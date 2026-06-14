#ifndef LOCAL_WRITER_H
#define LOCAL_WRITER_H

#include "shared.h"
#include "local_rules_engine.h"

void write_local_alert(const RuleInfo *rule, const char *log_msg, const char *location);

#endif
