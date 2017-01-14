//
// Created by lan on 12/20/16.
//
#ifndef CLINET_H
#define CLINET_H 1

#include "mon_value.h"
#include "cJSON.h"

#define MAX_METRIC_IN_A_HOST 100
#define BUFFER_SIZE 1024
#define SYS_CALL(RC, SYSCALL) \
    do {                      \
        RC = SYSCALL;         \
    } while (RC < 0 && errno == EINTR);

typedef g_val_t (*metric_func_void)(void);

typedef struct User {
    char *username;
    list_node *permission_list;
} User_t;

typedef struct Host {
    char *hostname;
    char *ip;
    hash_t *metrics;
    cJSON* send_data;

    pthread_mutex_t muttex;
} Host_t;

typedef struct metric_callback {
    monitor_value_msg msg;
    metric_func_void cb;
    g_val_t now;
    g_val_t last;
    float value_threshold;
    time_t next_collect;
    int collect_every;
} metric_callback_t;


typedef struct callback_options {
    char *name;
    monitor_value_types type;
    char *units;
    char *format;
    metric_func_void cb;
} callback_options_t;

cJSON *metric_value_to_cjson(monitor_value_msg *msg);
char *metric_value_to_str(monitor_value_msg *msg);
char *host_metric_type(monitor_value_types type);
#endif

