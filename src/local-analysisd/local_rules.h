#ifndef LOCAL_RULES_H
#define LOCAL_RULES_H

#include "shared.h"
#include "os_regex/os_regex.h"

typedef struct _local_rule {
    int id;
    int level;
    char *decoded_as;
    char *match;
    OSRegex regex;
    bool has_regex;
    char *description;
    struct _local_rule *next;
} local_rule;

local_rule *load_local_rules(const char *xml_path);
void free_local_rules(local_rule *rules);
local_rule *match_local_rules(const char *log_msg, const char *decoder_name, local_rule *rules_list);

#endif
