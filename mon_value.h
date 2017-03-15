//
// Created by lan on 12/20/16.
//
#ifndef GM_VALUE_H
#define GM_VALUE_H 1

#include <inttypes.h>
#include "uthash.h"

#define MAX_G_STRING_SIZE 64
typedef struct list_node {
    char string[MAX_G_STRING_SIZE];
    struct list_node *next, *prev;
} list_node;

typedef struct hash_struct {
    char key[MAX_G_STRING_SIZE];
    void        *data;
    UT_hash_handle hh;
} hash_t;

typedef struct list_hash_node {
    hash_t *hash;
    struct list_hash_node *next, *prev;
} list_hash_node;

typedef enum {
    MON_VALUE_UNKNOWN = 0,
    MON_VALUE_STRING = 1,
    MON_VALUE_UNSIGNED_16INT = 2,
    MON_VALUE_16INT = 3,
    MON_VALUE_UNSIGNED_32INT = 4,
    MON_VALUE_32INT = 5,
    MON_VALUE_FLOAT = 6,
    MON_VALUE_DOUBLE = 7,
    MON_VALUE_LIST = 8,
    MON_VALUE_HASH = 9,
    MON_VALUE_LIST_HASH = 10,
} monitor_value_types;

typedef union {
    int16_t int16;
    uint16_t uint16;
    int32_t int32;
    uint32_t uint32;
    float f;
    double d;
    char str[MAX_G_STRING_SIZE];
    hash_t *hash;
    list_node *list;
    list_hash_node *list_hash;
} g_val_t;

typedef struct {
    char *name;
    char *format;
    char *units;
    monitor_value_types type;
    g_val_t val;
} monitor_value_msg;

#endif  /* GM_VALUE_H */
