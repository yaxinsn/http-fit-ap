
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <debug_pub.h>

#include <utils/utils.h>
#include <utils/vty.h>
#include <utils/thread.h>
#include <utils/command.h>
#include <utils/log.h>
#include <utils/vector.h>
#include <utils/network.h>
#include <time.h>
#include "local.h"
#include "route.h"
#include <openssl/md5.h>
#include <stdio.h>
#include <curl/curl.h>



char* __url_key[]={
	"/m/getver",
	"/m/getvpnlist",
	"/m/putrouterstate",
	"/m/gettask",
	"/m/putkeys"
};


#define MD5_SIZE		16
#define MD5_STR_LEN     MD5_SIZE*2+1
int __md5(void* data,int len,void* ret)
{
    unsigned char md5_value[MD5_SIZE];
    char  md5_str[MD5_STR_LEN];
    int i;
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, data, len);
    
    //printf("---------%s:%d------\n",__func__,__LINE__);
    MD5_Final(md5_value,&md5);
    
    //printf("---------%s:%d------\n",__func__,__LINE__);
    for(i = 0; i < MD5_SIZE; i++)
    {
        snprintf(md5_str + i*2, 2+1, "%02x", md5_value[i]);
    }
    md5_str[MD5_STR_LEN] = '\0'; // add end
    //printf("---------%s:%d------\n",__func__,__LINE__);
    memcpy(ret,md5_str,MD5_STR_LEN);
    return 0;
}
static size_t function( void *ptr, size_t size, size_t nmemb, void *stream)
{
	memcpy((char*)stream,(char*)ptr,size*nmemb);
	return size*nmemb;
}
int send_msg(int type,char* msg,int len,char* recv,int* recvlen)
{
  CURL *curl;
  CURLcode res;
  char buf[2048] = {0};
  char url[128] = {0};
  char timerstamp_str[64] = {0};
  char signature[64] = {0};
  char slat_signature[64] = {0};
  char md5_key[64] = {0};
  
  struct curl_slist *headers=NULL; /* init to NULL is important */
  time_t a;
  time(&a);
  

  sprintf(slat_signature,"6ec42fced7f64e25bc5fd0c52ab2b637+%u",a);
  
  
  __md5(slat_signature,strlen(slat_signature),md5_key);
  
  sprintf(signature,"signature: %s",md5_key);
  
  sprintf(timerstamp_str,"timestamp: %u",a);
  headers = curl_slist_append(headers, timerstamp_str);
  headers = curl_slist_append(headers, signature);
  headers = curl_slist_append(headers, "Content-Type: application/json;charset=UTF-8 ");
 
  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl = curl_easy_init();
  if(curl) {
    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */
    sprintf(url,"http://v1.ipyun.cc%s",__url_key[type]);
    curl_easy_setopt(curl, CURLOPT_URL,url);
    /* Now specify the POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, msg); //todo it.
    /* Perform the request, res will get the return code */
	
	 curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,function);
	 curl_easy_setopt(curl,CURLOPT_WRITEDATA,buf);
	 curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
//	fprintf(stderr,"I am here <%s>\n",buf);
    *recvlen = strlen(buf);
    
    memcpy(recv,buf,*recvlen);
	
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  curl_slist_free_all(headers);
  if(res != CURLE_OK)
    return -1;
  return 0;
}





/******************************************************************/
//crypto function

