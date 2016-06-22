
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

#include <stdio.h>
#include <curl/curl.h>

enum msg_type {
MSG_TYPE_GETVER=0,
MSG_TYPE_GETVPN,
MSG_TYPE_PUTROUTESTATE, //  == getcmd.

MSG_TYPE_GETTASK,
MSG_TYPE_PUT_USER_SEARCH_KEYS,
	
	
};

char* __url_key[]={
	"/m/getVer",
	"/m/getVPN",
	"/m/putRouterState",
	"/m/getTask",
	"/m/putkeys"
};

int __send_msg()
{

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
  char buf[65535];

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl = curl_easy_init();
  if(curl) {
    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */
    curl_easy_setopt(curl, CURLOPT_URL, "http://ip.bj-ibook.cn/PutRouterInfo.jsp");
    /* Now specify the POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, msg); //todo it.

    /* Perform the request, res will get the return code */
	
	//fprintf(stdout,"I am here lala\n");
	 curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,function);
	 curl_easy_setopt(curl,CURLOPT_WRITEDATA,buf);
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
//	fprintf(stderr,"I am here <%s>\n",buf);
	
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return 0;
}





/******************************************************************/
//crypto function
