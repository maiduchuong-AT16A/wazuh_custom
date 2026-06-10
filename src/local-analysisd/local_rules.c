#include "local_rules.h"
#include "os_xml/os_xml.h"

local_rule *load_local_rules(const char *xml_path) {
    OS_XML xml;
    memset(&xml, 0, sizeof(xml));

    if (OS_ReadXML(xml_path, &xml) < 0) {
        merror("local-analysisd: Cannot read XML rules file '%s': %s", xml_path, xml.err);
        return NULL;
    }

    local_rule *head = NULL;
    local_rule *tail = NULL;

    xml_node **root_nodes = OS_GetElementsbyNode(&xml, NULL);
    if (!root_nodes) {
        OS_ClearXML(&xml);
        return NULL;
    }

    for (int i = 0; root_nodes[i]; i++) {
        if (strcmp(root_nodes[i]->element, "group") != 0) {
            continue;
        }

        xml_node **rule_nodes = OS_GetElementsbyNode(&xml, root_nodes[i]);
        if (!rule_nodes) {
            continue;
        }

        for (int j = 0; rule_nodes[j]; j++) {
            if (strcmp(rule_nodes[j]->element, "rule") != 0) {
                continue;
            }

            const char *id_str = w_get_attr_val_by_name(rule_nodes[j], "id");
            const char *level_str = w_get_attr_val_by_name(rule_nodes[j], "level");

            if (!id_str || !level_str) {
                mwarn("local-analysisd: Rule missing id or level attribute, skipping.");
                continue;
            }

            local_rule *r = calloc(1, sizeof(local_rule));
            if (!r) {
                merror("local-analysisd: Memory error.");
                continue;
            }
            r->id = atoi(id_str);
            r->level = atoi(level_str);

            xml_node **rule_childs = OS_GetElementsbyNode(&xml, rule_nodes[j]);
            if (rule_childs) {
                for (int k = 0; rule_childs[k]; k++) {
                    if (strcmp(rule_childs[k]->element, "decoded_as") == 0) {
                        r->decoded_as = strdup(rule_childs[k]->content);
                    } else if (strcmp(rule_childs[k]->element, "match") == 0) {
                        r->match = strdup(rule_childs[k]->content);
                    } else if (strcmp(rule_childs[k]->element, "regex") == 0) {
                        memset(&r->regex, 0, sizeof(r->regex));
                        if (OSRegex_Compile(rule_childs[k]->content, &r->regex, 0)) {
                            r->has_regex = true;
                        } else {
                            mwarn("local-analysisd: Failed to compile regex '%s' for rule %d", rule_childs[k]->content, r->id);
                        }
                    } else if (strcmp(rule_childs[k]->element, "description") == 0) {
                        r->description = strdup(rule_childs[k]->content);
                    }
                }
            }

            if (!head) {
                head = r;
            } else {
                tail->next = r;
            }
            tail = r;
        }
    }

    OS_ClearXML(&xml);
    return head;
}

void free_local_rules(local_rule *rules) {
    while (rules) {
        local_rule *tmp = rules;
        rules = rules->next;
        free(tmp->decoded_as);
        free(tmp->match);
        if (tmp->has_regex) {
            OSRegex_FreePattern(&tmp->regex);
        }
        free(tmp->description);
        free(tmp);
    }
}

local_rule *match_local_rules(const char *log_msg, const char *decoder_name, local_rule *rules_list) {
    local_rule *curr = rules_list;
    while (curr) {
        bool matched = true;

        if (curr->decoded_as && decoder_name) {
            if (strcmp(curr->decoded_as, decoder_name) != 0) {
                matched = false;
            }
        }

        if (matched && curr->match) {
            if (!strstr(log_msg, curr->match)) {
                matched = false;
            }
        }

        if (matched && curr->has_regex) {
            if (!OSRegex_Execute(log_msg, &curr->regex)) {
                matched = false;
            }
        }

        if (matched) {
            return curr;
        }

        curr = curr->next;
    }
    return NULL;
}
