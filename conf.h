//
// Created by lan on 12/20/16.
//
#ifndef CONF_H
#define CONF_H 1

typedef struct {
    char *hostname;
    int send_every;
    int debug_level;
    char *remote_host;
    unsigned short remote_port;
} config_t;

int parse_config_file(char *config_file);


#endif
