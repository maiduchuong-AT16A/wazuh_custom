/* wazuh-local-analysisd main entry point */
#include "shared.h"
#include "local_rules_engine.h"
#include "local_decoder_engine.h"
#include "local_eventinfo.h"
#include "local_cleanevent.h"
#include "local_writer.h"
#include "local_ar_config.h"
#include "local_exec.h"
#include "local_ai_enricher.h"
#include "os_net/os_net.h"
#include <dirent.h>

#define ARGV0 "wazuh-local-analysisd"

int run_foreground;

static void help_local_analysisd(char *home_path) __attribute((noreturn));

static int filter_xml(const struct dirent *ent) {
    size_t len = strlen(ent->d_name);
    if (len > 4 && strcmp(ent->d_name + len - 4, ".xml") == 0) {
        return 1;
    }
    return 0;
}

static void load_xml_directory(const char *dir_path, int is_rule, OSList* log_msg) {
    struct dirent **namelist;
    int n;
    char file_path[PATH_MAX];

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        minfo("wazuh-local-analysisd: current working directory: %s", cwd);
    }
    n = scandir(dir_path, &namelist, filter_xml, alphasort);
    if (n < 0) {
        merror_exit("Could not open directory %s: %s (errno %d)", dir_path, strerror(errno), errno);
    } else {
        for (int i = 0; i < n; i++) {
            snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, namelist[i]->d_name);
            if (is_rule) {
                minfo("wazuh-local-analysisd: Loading rule %s", file_path);
                if (Rules_OP_ReadRules(file_path, &os_analysisd_rulelist, NULL, &os_analysisd_last_events, &os_analysisd_decoder_store, log_msg, false) < 0) {
                    merror("Cannot read rule %s", file_path);
                }
            } else {
                minfo("wazuh-local-analysisd: Loading decoder %s", file_path);
                if (ReadDecodeXML(file_path, &os_analysisd_decoderlist_pn, &os_analysisd_decoderlist_nopn, &os_analysisd_decoder_store, log_msg) < 0) {
                    merror("Cannot read decoder %s", file_path);
                }
            }
            free(namelist[i]);
        }
        free(namelist);
    }
}

static void help_local_analysisd(char *home_path) {
    print_header();
    print_out("  %s: -[VhdfA] [-u user] [-g group] [-c config] [-q socket]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. Specify multiple times to increase debug level.");
    print_out("    -f          Run in foreground");
    print_out("    -A          AI-only mode (bypass all static rules and evaluate every event with AI)");
    print_out("    -R          Rule-only mode (disable AI enrichment hook)");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Local XML rules file (default: etc/local_rules.xml)");
    print_out("    -q <socket> Custom socket path to listen on (default: %s)", DEFAULTQUEUE);
    print_out(" ");
    os_free(home_path);
    exit(1);
}

int main(int argc, char **argv) {
    int c = 0;
    int debug_level = 0;
    char *home_path = w_homedir(argv[0]);

    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *socket_path = DEFAULTQUEUE;

    run_foreground = 0;
    int test_config = 0;
    int cli_ai_only = 0;
    int cli_rule_only = 0;

    /* Set process name */
    OS_SetName(ARGV0);


    /* Change working directory */
    if (chdir(home_path) == -1) {
        /* We can't use merror yet because logging is not initialized properly relative to home_path */
        fprintf(stderr, "wazuh-local-analysisd: Cannot chdir to %s: %s\\n", home_path, strerror(errno));
        os_free(home_path);
        exit(1);
    }

    int local_analysisd_debug_level = getDefine_Int("local_analysisd", "debug", 0, 2);

    while ((c = getopt(argc, argv, "VtdfhARu:g:D:c:q:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_local_analysisd(home_path);
                break;
            case 'd':
                nowDebug();
                debug_level++;
                break;
            case 'D':
                if (!optarg) merror_exit("-D needs an argument");
                os_free(home_path);
                os_strdup(optarg, home_path);
                if (chdir(home_path) == -1) {
                    merror_exit("Cannot chdir to %s: %s", home_path, strerror(errno));
                }
                break;

            case 'f':
                run_foreground = 1;
                break;
            case 'A':
                cli_ai_only = 1;
                break;
            case 'R':
                cli_rule_only = 1;
                break;
            case 't':
                test_config = 1;
                break;
            case 'u':
                if (!optarg) merror_exit("-u needs an argument");
                user = optarg;
                break;
            case 'g':
                if (!optarg) merror_exit("-g needs an argument");
                group = optarg;
                break;
            case 'c':
                if (!optarg) merror_exit("-c needs an argument");
                break;
            case 'q':
                if (!optarg) merror_exit("-q needs an argument");
                socket_path = optarg;
                break;
            default:
                help_local_analysisd(home_path);
                break;
        }
    }

    if (debug_level == 0) {
        debug_level = local_analysisd_debug_level;
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    minfo("wazuh-local-analysisd: Starting daemon (PID: %d)", (int)getpid());

    /* Check if the user/group given are valid */
    uid_t uid = Privsep_GetUser(user);
    gid_t gid = Privsep_GetGroup(group);
    if (uid == (uid_t)-1 || gid == (gid_t)-1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Go daemon mode if foreground is not set and not testing config */
    if (!run_foreground && !test_config) {
        goDaemon();
    }

    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR, ARGV0, errno, strerror(errno));
    }

    /* Start the signal manipulation */
    StartSIG(ARGV0);

    /* Load Active Response configuration */
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        minfo("wazuh-local-analysisd: Current working directory: %s", cwd);
    }
    minfo("wazuh-local-analysisd: Loading Active Response configuration...");
    if (local_ar_config_init("etc/ossec.conf") < 0) {
        mwarn("wazuh-local-analysisd: Could not load Active Response config from etc/ossec.conf");
    }

    if (cli_ai_only) {
        Config.ai_only = 1;
    }
    if (cli_rule_only) {
        Config.rule_only = 1;
        Config.ai_only = 0;
    }

    minfo("wazuh-local-analysisd: Detection mode: %s",
          Config.ai_only ? "AI-ONLY (Static rules bypassed)" :
          (Config.rule_only ? "RULE-ONLY (AI disabled)" : "HYBRID (Static rules + AI)"));

    if (test_config) {
        minfo("wazuh-local-analysisd: Configuration validated successfully. Exiting.");
        exit(0);
    }

    /* Load local rules configuration (only needed when not in AI-Only mode) */
    if (!Config.ai_only) {
        minfo("wazuh-local-analysisd: Loading XML decoders and rules...");
        OSList* log_msg = OSList_Create();

        OS_CreateOSDecoderList();
        OS_CreateRuleList();

        if (access("etc/shared/ruleset/decoders", F_OK) == 0) {
            load_xml_directory("etc/shared/ruleset/decoders", 0, log_msg);
            if (access("etc/shared/etc/decoders", F_OK) == 0) {
                load_xml_directory("etc/shared/etc/decoders", 0, log_msg);
            }
        } else {
            load_xml_directory("ruleset/decoders", 0, log_msg);
            load_xml_directory("etc/decoders", 0, log_msg);
        }
        SetDecodeXML(log_msg, &os_analysisd_decoder_store, &os_analysisd_decoderlist_nopn, &os_analysisd_decoderlist_pn);

        os_calloc(1, sizeof(EventList), os_analysisd_last_events);
        OS_CreateEventList(256, os_analysisd_last_events);

        if (access("etc/shared/ruleset/rules", F_OK) == 0) {
            load_xml_directory("etc/shared/ruleset/rules", 1, log_msg);
            if (access("etc/shared/etc/rules", F_OK) == 0) {
                load_xml_directory("etc/shared/etc/rules", 1, log_msg);
            }
        } else {
            load_xml_directory("ruleset/rules", 1, log_msg);
            load_xml_directory("etc/rules", 1, log_msg);
        }

        _setlevels(OS_GetFirstRule(), 0);

        minfo("wazuh-local-analysisd: Successfully loaded Rules and Decoders.");
    } else {
        minfo("wazuh-local-analysisd: AI-ONLY mode active, skipping XML decoders and rules loading.");
    }

    /* Bind Unix domain socket (DGRAM) */
    minfo("wazuh-local-analysisd: Listening on Unix socket '%s'", socket_path);
    int sock = OS_BindUnixDomainWithPerms(socket_path, SOCK_DGRAM, OS_MAXSTR + 512, uid, gid, 0660);
    if (sock < 0) {
        merror("wazuh-local-analysisd: Unable to bind socket '%s': %s (%d)", socket_path, strerror(errno), errno);
        exit(1);
    }

    /* Change user/group if configured */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    char msg[OS_MAXSTR + 1];
    msg[OS_MAXSTR] = '\0';

    /* Main processing loop */
    while (1) {
        ssize_t recv_b = recv(sock, msg, OS_MAXSTR, 0);
        if (recv_b < 0) {
            if (errno == EINTR) continue;
            merror("wazuh-local-analysisd: Socket recv error: %s (%d)", strerror(errno), errno);
            break;
        }

        msg[recv_b] = '\0';
        mdebug2("wazuh-local-analysisd: Raw event received: %s", msg);

        /* Process Event */
        Eventinfo *lf;
        os_calloc(1, sizeof(Eventinfo), lf);
        os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
        Zero_Eventinfo(lf);
        
        if (OS_CleanMSG(msg, lf) < 0) {
            w_free_event_info(lf);
            continue; // Could not parse
        }

        if (Config.ai_only) {
            /* AI-Only Mode: bypass decoders and static rules, evaluate every event with AI */
            local_ai_enrich_event(lf, msg);
            w_free_event_info(lf);
            continue;
        }
        
        regex_matching decoder_match;
        memset(&decoder_match, 0, sizeof(regex_matching));
        
        DecodeEvent(lf, NULL, &decoder_match, os_analysisd_decoderlist_nopn);
        if (lf->program_name) {
            DecodeEvent(lf, NULL, &decoder_match, os_analysisd_decoderlist_pn);
        }
        
        RuleNode *rulenode_pt = OS_GetFirstRule();
        RuleInfo *matched_rule = NULL;

        if (rulenode_pt) {
            do {
                /* Categories must match (same as analysisd.c) */
                if (lf->decoder_info && rulenode_pt->ruleinfo->category != lf->decoder_info->type) {
                    continue;
                }

                /* Check each rule in the category tree */
                if (matched_rule = OS_CheckIfRuleMatch(lf, os_analysisd_last_events, NULL,
                                                       rulenode_pt, &decoder_match,
                                                       NULL, NULL, false, NULL), !matched_rule) {
                    continue;
                }

                /* Ignore level 0 */
                if (matched_rule->level == 0) {
                    break;
                }

                /* Log the alert if configured to (DO_LOGALERT based on Config.logbylevel) */
                if (matched_rule->alert_opts & DO_LOGALERT) {
                    mdebug1("wazuh-local-analysisd: Detection successful for rule ID %d (level %d)", matched_rule->sigid, matched_rule->level);
                    write_local_alert(matched_rule, lf->full_log ? lf->full_log : msg, lf->location);
                }

                /* Trigger Active Responses */
                if (matched_rule->ar) {
                    minfo("wazuh-local-analysisd: Rule %d has AR attached!", matched_rule->sigid);
                    for (int i = 0; matched_rule->ar[i]; i++) {
                        active_response *ar = matched_rule->ar[i];
                        minfo("wazuh-local-analysisd: Triggering AR: %s", ar->name);
                        local_OS_Exec(ar, lf, matched_rule, msg);
                    }
                } else {
                    mdebug2("wazuh-local-analysisd: Rule %d has NO AR attached.", matched_rule->sigid);
                }

                /* State tracking for if_matched_sid (for all matched rules with level > 0) */
                if (matched_rule->sid_prev_matched) {
                    OSListNode *node;
                    w_mutex_lock(&matched_rule->mutex);
                    if (node = OSList_AddData(matched_rule->sid_prev_matched, lf), !node) {
                        merror("Unable to add data to sig list.");
                    } else {
                        lf->sid_node_to_delete = node;
                    }
                    w_mutex_unlock(&matched_rule->mutex);
                }
                /* Group list */
                else if (matched_rule->group_prev_matched) {
                    unsigned int j = 0;
                    OSListNode *node;

                    w_mutex_lock(&matched_rule->mutex);
                    os_calloc(matched_rule->group_prev_matched_sz, sizeof(OSListNode *), lf->group_node_to_delete);
                    while (j < matched_rule->group_prev_matched_sz) {
                        if (node = OSList_AddData(matched_rule->group_prev_matched[j], lf), !node) {
                            merror("Unable to add data to grp list.");
                        } else {
                            lf->group_node_to_delete[j] = node;
                        }
                        j++;
                    }
                    w_mutex_unlock(&matched_rule->mutex);
                }

                lf->queue_added = 1;
                OS_AddEvent(lf, os_analysisd_last_events);
                break;
            } while ((rulenode_pt = rulenode_pt->next) != NULL);
        }

        /* AI enrichment hook for events that did not generate a static rule alert */
        if (!Config.rule_only && (!matched_rule || !(matched_rule->alert_opts & DO_LOGALERT))) {
            local_ai_enrich_event(lf, msg);
        }

        if (!lf->queue_added) {
            w_free_event_info(lf);
        }
    }

    /* Cleanup */
    close(sock);
    unlink(socket_path);
    minfo("wazuh-local-analysisd: Stopped.");
    return 0;
}
