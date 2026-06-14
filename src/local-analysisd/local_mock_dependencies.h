#ifndef LOCAL_MOCK_DEPENDENCIES_H
#define LOCAL_MOCK_DEPENDENCIES_H

#include "shared.h"

/* Missing constants */
#define LR_STRING_MATCH 0
#define LR_STRING_NOT_MATCH 1
#define LR_STRING_MATCH_VALUE 2
#define LR_ADDRESS_MATCH 10
#define LR_ADDRESS_NOT_MATCH 11
#define LR_ADDRESS_MATCH_VALUE 12

extern char __shost[512];
extern int __crt_wday;

/* Mock for smwarn and smerror (logmsg) */
#define smwarn(list, msg, ...) mwarn(msg, ##__VA_ARGS__)
#define smerror(list, msg, ...) merror(msg, ##__VA_ARGS__)

/* Mock for active-response.h */
typedef struct _ar_command {
    int timeout_allowed;
    char *name;
    char *executable;
    char *extra_args;
} ar_command;

typedef struct _ar {
    int timeout;
    int location;
    int level;
    char *name;
    char *command;
    char *agent_id;
    char *rules_id;
    char *rules_group;
    ar_command *ar_cmd;
} active_response;

extern OSList *active_responses;

/* Mock for lists.h */
typedef struct ListNode {
    int loaded;
    char *cdb_filename;
    char *txt_filename;
    void *cdb;
    struct ListNode *next;
    pthread_mutex_t mutex;
} ListNode;

typedef struct ListRule {
    int loaded;
    int field;
    int lookup_type;
    OSMatch *matcher;
    char *dfield;
    char *filename;
    ListNode *db;
    struct ListRule *next;
    pthread_mutex_t mutex;
} ListRule;

/* Mock for Config */
typedef struct _Config {
    int decoder_order_size;
    void *labels;
    int mailbylevel;
    int logbylevel;
    OSHash *g_rules_hash;
} _Config;
extern _Config Config;

/* Mock for plugin decoders */
extern const char *(plugin_decoders[]);
extern void *(plugin_decoders_init[]);
extern void *(plugin_decoders_exec[]);

/* Mock for compiled rules */
extern const char *(compiled_rules_name[]);
extern void *(compiled_rules_list[]);

/* Mock for NULL_Decoder */
extern void *NULL_Decoder;

/* Mock for missing functions */
struct _Eventinfo;
ListRule *OS_AddListRule(ListRule *first_rule_list, int lookup_type, int field,
                         const char *dfield, char *listname, OSMatch *matcher,
                         ListNode **l_node);
int OS_DBSearch(ListRule *lrule, char *key, ListNode **l_node);
char *FTS(struct _Eventinfo *lf, OSList **fts_list, OSHash **fts_store);
#define w_guard_mutex_variable(mutex, var) do { (var); } while(0)
time_t w_get_current_time(void);

#endif
