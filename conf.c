//
// Created by lan on 12/20/16.
//
#include <string.h>
#include "conf.h"
#include "cJSON.h"
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include "metrics.h"
#include "client.h"
#include "net.h"
#include "file.h"
#include "mon_value.h"

#define HOST_NAME_MAX_LENGTH 256
extern hash_t *host_data;
extern g_socket *tcp_client_socket;
extern g_socket *tcp_server_socket;

config_t config;
hash_t *callback_options_hash = NULL;

static callback_options_t callback_options[] = {
    {"cpu_num", MON_VALUE_UNSIGNED_16INT, "CPUs", "%hu", cpu_num_func},
    {"cpu_speed", MON_VALUE_UNSIGNED_32INT, "MHz", "%u", cpu_speed_func},
    {"mem_total", MON_VALUE_FLOAT, "KB", "%.0f", mem_total_func},
    {"swap_total", MON_VALUE_FLOAT, "KB", "%.0f", swap_total_func},

    {"cpu_user", MON_VALUE_FLOAT, "%", "%.1f", cpu_user_func},
    {"cpu_nice", MON_VALUE_FLOAT, "%", "%.1f", cpu_nice_func},
    {"cpu_steal", MON_VALUE_FLOAT, "%", "%.1f", cpu_steal_func},
    {"cpu_sintr", MON_VALUE_FLOAT, "%", "%.1f", cpu_sintr_func},
    {"cpu_system", MON_VALUE_FLOAT, "%", "%.1f", cpu_system_func},
    {"cpu_idle", MON_VALUE_FLOAT, "%", "%.1f", cpu_idle_func},
    {"cpu_aidle", MON_VALUE_FLOAT, "%", "%.1f", cpu_aidle_func},
    {"cpu_wio", MON_VALUE_FLOAT, "%", "%.1f", cpu_wio_func},

    {"bytes_out", MON_VALUE_FLOAT, "bytes/sec", "%.3f",  bytes_out_func},
    {"bytes_in", MON_VALUE_FLOAT, "bytes/sec", "%.3f",  bytes_in_func},
    {"pkts_in", MON_VALUE_FLOAT, "packets/sec", "%.3f",  pkts_in_func},
    {"pkts_out", MON_VALUE_FLOAT, "packets/sec", "%.3f",  pkts_out_func},

    {"disk_total", MON_VALUE_DOUBLE, "GB", "%.3f",  disk_total_func},
    {"disk_free", MON_VALUE_DOUBLE, "GB", "%.3f",  disk_free_func},

    {"mem_total", MON_VALUE_FLOAT, "KB", "%.0f", mem_total_func},
    {"mem_free",MON_VALUE_FLOAT, "KB", "%.0f", mem_free_func},
    {"mem_shared",MON_VALUE_FLOAT, "KB", "%.0f", mem_shared_func},
    {"mem_buffers", MON_VALUE_FLOAT, "KB", "%.0f", mem_buffers_func},
    {"mem_cached", MON_VALUE_FLOAT, "KB", "%.0f", mem_cached_func},
    {"swap_free", MON_VALUE_FLOAT, "KB", "%.0f", swap_free_func},
    {"swap_total", MON_VALUE_FLOAT, "KB", "%.0f", swap_total_func},

    {"test_list", MON_VALUE_LIST, "", "", test_list},
    {"test_net_hash", MON_VALUE_HASH, "", "", test_net_hash},
    {"ip_test", MON_VALUE_LIST_HASH, "", "", ip_test_func},
    {NULL}
};
typedef const void (*conf_func)(cJSON *);

void set_default_config()
{
    config.send_every = 20;
    config.debug_level = 1;
    config.hostname = malloc(HOST_NAME_MAX_LENGTH);
    gethostname(config.hostname, HOST_NAME_MAX_LENGTH);
}

cJSON *get_host_info(Host_t *host)
{
    if (host) {
        char ip[16];
        get_localip(ip);
        strcpy(host->hostname, config.hostname);
        strcpy(host->ip, ip);
        cJSON *host_info = cJSON_CreateObject();
        cJSON_AddStringToObject(host_info, "hostname", host->hostname);
        cJSON_AddStringToObject(host_info, "ip", host->ip);
        cJSON_AddNumberToObject(host_info, "localtime", 0);
        g_val_t val = boottime_func();
        cJSON_AddNumberToObject(host_info, "boottime", val.int32);
        val = mac_address_func();
        cJSON_AddStringToObject(host_info, "mac_address", val.str);

        return host_info;
    } else {
        return NULL;
    }
}

void get_global_val(cJSON *json)
{
    cJSON *global = cJSON_GetObjectItem(json, "global");
    if (global) {
        cJSON *val;
        if (val = cJSON_GetObjectItem(global, "hostname")) {
            strcpy(config.hostname, val->valuestring);
        }
        if (val = cJSON_GetObjectItem(global, "debug_level")) {
            config.debug_level = val->valueint;
        }
    }
}

void create_sockets(cJSON *json)
{
    cJSON *channel, *host, *port;
    
    if (channel = cJSON_GetObjectItem(json, "tcp_client_channel")) {
        if ((host = cJSON_GetObjectItem(channel, "host"))
            && (port = cJSON_GetObjectItem(channel, "port"))) {
            tcp_client_socket = tcp_socket_client(host->valuestring, port->valueint);
            config.remote_host = malloc(MAX_G_STRING_SIZE);
            strcpy(config.remote_host, host->valuestring);
            config.remote_port = port->valueint;
        }
    } else {
        err_quit("Can't find remote host.\n");
    }

    if (channel = cJSON_GetObjectItem(json, "tcp_accept_channel")) {
        if (port = cJSON_GetObjectItem(channel, "port")) {
            tcp_server_socket = tcp_socket_server(port->valueint);

            if (!tcp_server_socket) {
                err_quit("Create server socket failed.\n");
            }
        }
    } else {
        err_quit("Can't find tcp_accept_channel.\n");
    }

}

/**
 * get which metrics need collect
 * @param json
 */
void get_metric_callbacks(cJSON *json)
{
    int i;

    cJSON *collection_group = cJSON_GetObjectItem(json, "collection_group");
    cJSON *is_in_rrd = cJSON_GetObjectItem(json, "is_in_rrd");
    host_data = NULL;
    if (collection_group && collection_group->child) {
        cJSON *ptr = collection_group->child;
        while (ptr) {
            Host_t *host = (Host_t*)malloc(sizeof(Host_t));
            host->hostname = malloc(MAX_G_STRING_SIZE);
            host->ip = malloc(MAX_G_STRING_SIZE);
            host->send_data = cJSON_CreateObject();
            cJSON_AddItemToObject(host->send_data, "host", get_host_info(host));
            host->metrics = NULL;
            cJSON *metrics = cJSON_CreateObject();
            for (i = 0;i < cJSON_GetArraySize(ptr);i++) {
                cJSON *metric = cJSON_GetArrayItem(ptr,i);
                cJSON *name = cJSON_GetObjectItem(metric, "name");
                if (name) {
                    hash_t *node = NULL;
                    HASH_FIND_STR(callback_options_hash, name->valuestring, node);

                    if (node) {
                        callback_options_t *option = (callback_options_t*)node->data;

                        metric_callback_t *metric_callback = malloc(sizeof(metric_callback_t));
                        if (!metric_callback) {
                            err_quit("Unable to create memory.\n");
                        }

                        metric_callback->cb = option->cb;
                        metric_callback->msg.type = option->type;

                        metric_callback->msg.name = malloc(strlen(name->valuestring) + 1);
                        strcpy(metric_callback->msg.name, name->valuestring);

                        metric_callback->msg.format = malloc(strlen(option->format) + 1);
                        strcpy(metric_callback->msg.format, option->format);
                        metric_callback->msg.units = malloc(strlen(option->units) + 1);
                        strcpy(metric_callback->msg.units, option->units);

                        cJSON *collect_every = cJSON_GetObjectItem(metric, "collect_every");
                        if (collect_every) {
                            metric_callback->collect_every = collect_every->valueint;
                            metric_callback->next_collect = 0;
                        } else {
                            metric_callback->collect_every = -1;
                            metric_callback->next_collect = 0;
                        }

                        hash_t *node = (hash_t*)malloc(sizeof(hash_t));
                        strcpy(node->key, metric_callback->msg.name);
                        node->data = metric_callback;
                        HASH_ADD_STR(host->metrics, key, node);

                        cJSON *metric = cJSON_CreateObject();
                        cJSON_AddStringToObject(metric, "units", metric_callback->msg.units);
                        cJSON_AddStringToObject(metric, "type", host_metric_type(metric_callback->msg.type));
                        cJSON* item;
                        switch (metric_callback->msg.type) {
                            case MON_VALUE_LIST:
                            case MON_VALUE_LIST_HASH:
                                item = cJSON_CreateArray();
                                cJSON_AddItemToObject(metric, "value", item);
                                break;
                            case MON_VALUE_HASH:
                                item = cJSON_CreateObject();
                                cJSON_AddItemToObject(metric, "value", item);
                                break;
                            default:
                                cJSON_AddStringToObject(metric, "value", "");
                                break;
                        }


                        int b = 1;
                        if (is_in_rrd) {
                            cJSON *metric_is_in_rrd = cJSON_GetObjectItem(is_in_rrd, metric_callback->msg.name);
                            b = metric_is_in_rrd ? metric_is_in_rrd->valueint : 1;
                        }
                        if (metric_callback->msg.type == MON_VALUE_STRING ||
                            metric_callback->msg.type == MON_VALUE_LIST ||
                            metric_callback->msg.type == MON_VALUE_HASH ||
                            metric_callback->msg.type == MON_VALUE_LIST_HASH) {
                            b = 0;
                        }
                        debug_msg("%s is_in_rrd: %d", metric_callback->msg.name, b);

                        cJSON_AddBoolToObject(metric, "is_in_rrd", b);

                        cJSON_AddItemToObject(metrics, metric_callback->msg.name, metric);
                    }
                }
            }
            cJSON_AddItemToObject(host->send_data, "metrics", metrics);
            hash_t *node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, ptr->string);
            node->data = host;
            HASH_ADD_STR(host_data, key, node);
            ptr = ptr->next;
        }

    }
    
}

void init_callback_hash() 
{
    int i;

    for (i = 0;callback_options[i].name != NULL;i++) {
        hash_t *node = (hash_t*)malloc(sizeof(hash_t));
        strcpy(node->key, callback_options[i].name);
        node->data = &(callback_options[i]);

        HASH_ADD_STR(callback_options_hash, key, node);
    }

}

static conf_func conf_funcs[] = {
        get_global_val,
        get_metric_callbacks,
        create_sockets,
        NULL
};

int parse_config_file (char *config_file)
{
    cJSON *json;
    init_callback_hash();
    set_default_config();

    char *data = NULL;
    slurpfile(config_file, &data, BUFFSIZE);
    json = cJSON_Parse(data);
    if (!json) {
        err_quit("Error before: [%s]\n",cJSON_GetErrorPtr());
    }
    debug_msg(data);

    int i;
    for (i = 0; conf_funcs[i]; i++) {
        conf_funcs[i](json);
    }

    hash_t *node, *tmp;
    HASH_ITER(hh, callback_options_hash, node, tmp) {
        HASH_DEL(callback_options_hash, node);
        free(node);
    }
    free(callback_options_hash);
    cJSON_Delete(json);
    free(data);
    return 0;
}





