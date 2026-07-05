/* wazuh-local-analysisd - local_ar_config.c
 * Load Active Response configuration
 */

#include "shared.h"
#include "config/config.h"
#include "os_xml/os_xml.h"
#include "config/active-response.h"
#include "local_mock_dependencies.h"

int local_ar_config_init(const char *cfg_file) {
    OS_XML xml;
    XML_NODE node;
    XML_NODE child;
    int i, j;
    FILE *fp;

    if (!active_responses) {
        active_responses = OSList_Create();
    }
    OSList *commands = OSList_Create();

    if (OS_ReadXML(cfg_file, &xml) < 0) {
        merror("wazuh-local-analysisd: Cannot read XML config '%s': %s", cfg_file, xml.err);
        return -1;
    }

    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        OS_ClearXML(&xml);
        return -1;
    }

    /* Empty the DEFAULTAR file before parsing (as analysisd does) */
    fp = wfopen(DEFAULTAR, "w");
    if (fp) {
        fclose(fp);
    } else {
        merror(FOPEN_ERROR, DEFAULTAR, errno, strerror(errno));
    }

#ifndef WIN32
    gid_t gr_gid = Privsep_GetGroup(GROUPGLOBAL);
    if (gr_gid != (gid_t)-1) {
        chown(DEFAULTAR, (uid_t) - 1, gr_gid);
    }
#endif
    chmod(DEFAULTAR, 0640);

    /* Pass 1: Parse commands */
    for (i = 0; node[i]; i++) {
        if (!node[i]->element) continue;
        if (strcmp(node[i]->element, "ossec_config") == 0) {
            child = OS_GetElementsbyNode(&xml, node[i]);
            if (child) {
                for (j = 0; child[j]; j++) {
                    if (!child[j]->element) continue;
                    if (strcmp(child[j]->element, "command") == 0) {
                        XML_NODE cmd_node = OS_GetElementsbyNode(&xml, child[j]);
                        if (cmd_node) {
                            ReadActiveCommands(cmd_node, commands, NULL);
                            OS_ClearNode(cmd_node);
                        }
                    }
                }
                OS_ClearNode(child);
            }
        }
    }

    /* Pass 2: Parse active-responses */
    for (i = 0; node[i]; i++) {
        if (!node[i]->element) continue;
        if (strcmp(node[i]->element, "ossec_config") == 0) {
            child = OS_GetElementsbyNode(&xml, node[i]);
            if (child) {
                for (j = 0; child[j]; j++) {
                    if (!child[j]->element) continue;
                    if (strcmp(child[j]->element, "active-response") == 0) {
                        XML_NODE ar_node = OS_GetElementsbyNode(&xml, child[j]);
                        if (ar_node) {
                            ReadActiveResponses(ar_node, commands, active_responses);
                            OS_ClearNode(ar_node);
                        }
                    }
                }
                OS_ClearNode(child);
            }
        }
    }

    OS_ClearNode(node);
    OS_ClearXML(&xml);

    /* Print loaded Active Responses */
    if (active_responses) {
        OSListNode *ar_node_list;
        active_response *ar;
        int ar_count = 0;

        ar_node_list = OSList_GetFirstNode(active_responses);
        while (ar_node_list) {
            ar = (active_response *)ar_node_list->data;
            minfo("wazuh-local-analysisd: [Active Response] Status: ENABLED | name: '%s' | command: '%s' | timeout: %d | level: %d | location: %d",
                  ar->name, ar->command, ar->timeout, ar->level, ar->location);
            ar_count++;
            ar_node_list = OSList_GetNextNode(active_responses);
        }
        
        if (ar_count > 0) {
            minfo("wazuh-local-analysisd: Active Response feature is globally ENABLED (Loaded: %d, Flag: %d)", ar_count, ar_flag);
        } else {
            minfo("wazuh-local-analysisd: Active Response feature is globally DISABLED (0 configurations loaded)");
        }
    } else {
        minfo("wazuh-local-analysisd: Active Response feature is globally DISABLED (List uninitialized)");
    }

    return 0;
}
