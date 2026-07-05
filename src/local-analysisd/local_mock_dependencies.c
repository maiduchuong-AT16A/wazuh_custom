#include "local_mock_dependencies.h"
#include "local_eventinfo.h"

char __shost[512] = "localhost";
int __crt_wday = 0;

_Config Config = {
    .decoder_order_size = 256,
    .labels = NULL,
    .mailbylevel = 10,
    .logbylevel = 10,
    .g_rules_hash = NULL
};

const char *(plugin_decoders[]) = { NULL };
void *(plugin_decoders_init[]) = { NULL };
void *(plugin_decoders_exec[]) = { NULL };

const char *(compiled_rules_name[]) = { NULL };

void *(compiled_rules_list[]) = { NULL };

void *NULL_Decoder = NULL;

OSList *active_responses = NULL;

ListRule *OS_AddListRule(ListRule *first_rule_list, int lookup_type, int field,
                         const char *dfield, char *listname, OSMatch *matcher,
                         ListNode **l_node) {
    return first_rule_list;
}

int OS_DBSearch(ListRule *lrule, char *key, ListNode **l_node) {
    return 0;
}

char *FTS(struct _Eventinfo *lf, OSList **fts_list, OSHash **fts_store) {
    return NULL;
}



time_t w_get_current_time(void) {
    return time(NULL);
}

int doDiff(RuleInfo *rule, struct _Eventinfo *lf) {
    return 0;
}

void os_remove_cdbrules(ListRule **l_rule) {
    /* Dummy */
}
