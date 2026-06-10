#ifndef LOCAL_WRITER_H
#define LOCAL_WRITER_H

#include "shared.h"
#include "local_rules.h"

void write_local_alert(const local_rule *rule, const char *log_msg, const char *location);

#endif
