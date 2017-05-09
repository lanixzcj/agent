
//
// Created by can on 17-5-3.
//

#ifndef C_SAFE_H
#define C_SAFE_H
#include "debug_msg.h"
#include "cstdlib"
#include <string>
#include <iostream>
#include <fstream>
#include "cJSON.h"
void safer(char *data);
void net_safer(cJSON *json);
void file_safer(cJSON *json);
#endif //C_SAFE_H
