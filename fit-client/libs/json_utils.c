

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <utils/utils.h>
#include <utils/vty.h>
#include <utils/thread.h>
#include <utils/command.h>
#include <utils/log.h>
#include <utils/vector.h>
#include <utils/network.h>

#include <net/route.h>
#include <net/if.h>
#include "json-utils.h"
/****************************sjon**********************************/


json_object* create_sjon_from_string(char* str)
{
    json_object *new_obj = json_tokener_parse(str);
    return new_obj;
    
}

const char* find_value_from_sjon_by_key(json_object* obj,char* skey)
{
   //return json_object_to_json_string(json_object_object_get(obj,skey));
   #if 1
      json_object_object_foreach(obj, key, val) {
        if(!strcmp(skey,key))
            return json_object_to_json_string(val);

            
   // printf("\t%s: %s\n", key, json_object_to_json_string(val));
  }
  return NULL;
  #endif
}

const json_object* find_value_from_json_object_by_key(json_object* obj,char* skey)
{
   //return json_object_to_json_string(json_object_object_get(obj,skey));
   #if 1
      json_object_object_foreach(obj, key, val) {
        if(!strcmp(skey,key))
            return (val);

            
   // printf("\t%s: %s\n", key, json_object_to_json_string(val));
  }
  return NULL;
  #endif
}
void free_json(json_object* obj)
{
    json_object_put(obj);
}

char* find_value_from_sjon_by_key2(json_object* obj,char* skey)
{
    char* v_b=0;
    const char* v_j;
    
  json_object_object_foreach(obj, key, val) {
      if(!strcmp(skey,key)){
          v_j = json_object_to_json_string(val);            
          v_b = malloc(strlen(v_j)+1);
          if(v_b){
            memset(v_b,0,strlen(v_j)+1);
            strncpy(v_b,v_j,strlen(v_j));
          }
          return v_b;
      }
  }
  return NULL;
  
}

