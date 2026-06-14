/* wazuh-local-analysisd main entry point */
#include "shared.h"
#include "local_rules.h"
#include "local_writer.h"
#include "os_net/os_net.h"

#define ARGV0 "wazuh-local-analysisd"

int run_foreground;

static void help_local_analysisd(char *home_path) __attribute((noreturn));

static void help_local_analysisd(char *home_path) {
    print_header();
    print_out("  %s: -[Vhdf] [-u user] [-g group] [-c config] [-q socket]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. Specify multiple times to increase debug level.");
    print_out("    -f          Run in foreground");
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
    const char *cfg_path = "etc/local_rules.xml";
    const char *socket_path = DEFAULTQUEUE;

    run_foreground = 0;

    /* Set process name */
    OS_SetName(ARGV0);

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror(CHDIR_ERROR, home_path, errno, strerror(errno));
        os_free(home_path);
        exit(1);
    }

    int local_analysisd_debug_level = getDefine_Int("local_analysisd", "debug", 0, 2);

    while ((c = getopt(argc, argv, "Vtdfhu:g:D:c:q:")) != -1) {
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
            case 'f':
                run_foreground = 1;
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
                cfg_path = optarg;
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

    os_free(home_path);
    minfo("wazuh-local-analysisd: Starting daemon (PID: %d)", (int)getpid());

    /* Check if the user/group given are valid */
    uid_t uid = Privsep_GetUser(user);
    gid_t gid = Privsep_GetGroup(group);
    if (uid == (uid_t)-1 || gid == (gid_t)-1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Go daemon mode if foreground is not set */
    if (!run_foreground) {
        goDaemon();
    }

    /* Start the signal manipulation */
    StartSIG(ARGV0);

    /* Load local rules configuration */
    minfo("wazuh-local-analysisd: Loading XML rules from '%s'", cfg_path);
    local_rule *rules_list = load_local_rules(cfg_path);
    if (!rules_list) {
        merror("wazuh-local-analysisd: Failed to load rules from '%s'. Exiting.", cfg_path);
        exit(1);
    }

    int rule_count = 0;
    local_rule *tmp = rules_list;
    while (tmp) {
        rule_count++;
        tmp = tmp->next;
    }
    minfo("wazuh-local-analysisd: Successfully loaded %d rules.", rule_count);

    /* Bind Unix domain socket (DGRAM) */
    minfo("wazuh-local-analysisd: Listening on Unix socket '%s'", socket_path);
    int sock = OS_BindUnixDomainWithPerms(socket_path, SOCK_DGRAM, OS_MAXSTR + 512, uid, gid, 0660);
    if (sock < 0) {
        merror("wazuh-local-analysisd: Unable to bind socket '%s': %s (%d)", socket_path, strerror(errno), errno);
        free_local_rules(rules_list);
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

        /* Parse log format: loc:locmsg:message */
        char *p = strchr(msg, ':');
        if (p) {
            char *locmsg = p + 1;
            char *message = NULL;

            char *arrow = strstr(locmsg, "->");
            if (arrow) {
                *arrow = '\0';
                message = arrow + 2;
            } else {
                char *colon = strchr(locmsg, ':');
                if (colon) {
                    *colon = '\0';
                    message = colon + 1;
                }
            }

            if (message) {
                mdebug2("wazuh-local-analysisd: Extracted location: '%s', message: '%s'", locmsg, message);

                /* Match against local rules */
                local_rule *matched_rule = match_local_rules(message, locmsg, rules_list);
                if (matched_rule) {
                    mdebug1("wazuh-local-analysisd: Detection successful for rule ID %d (level %d)", matched_rule->id, matched_rule->level);
                    /* Write alert locally */
                    write_local_alert(matched_rule, message, locmsg);
                }
            }
        }
    }

    /* Cleanup */
    close(sock);
    unlink(socket_path);
    free_local_rules(rules_list);
    minfo("wazuh-local-analysisd: Stopped.");
    return 0;
}
