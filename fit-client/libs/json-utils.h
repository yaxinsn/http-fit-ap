
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "json-c/json.h"

json_object* create_sjon_from_string(char* str);
const char* find_value_from_sjon_by_key(json_object* obj,char* skey);

void free_json(json_object* obj);
char* find_value_from_sjon_by_key2(json_object* obj,char* skey);
