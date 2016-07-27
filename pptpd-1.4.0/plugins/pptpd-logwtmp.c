/*
 * $Id: pptpd-logwtmp.c,v 1.6 2013/02/07 00:37:39 quozl Exp $
 * pptpd-logwtmp.c - pppd plugin to update wtmp for a pptpd user
 *
 * Copyright 2004 James Cameron.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */
#include <unistd.h>
#include <utmp.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <pppd/pppd.h>

char pppd_version[] = VERSION;

static char pptpd_original_ip[PATH_MAX+1];
static bool pptpd_logwtmp_strip_domain = 0;

static option_t options[] = {
  { "pptpd-original-ip", o_string, pptpd_original_ip,
    "Original IP address of the PPTP connection",
    OPT_STATIC, NULL, PATH_MAX },
  { "pptpd-logwtmp-strip-domain", o_bool, &pptpd_logwtmp_strip_domain,
    "Strip domain from username before logging", OPT_PRIO | 1 },
  { NULL }
};

static char *reduce(char *user)
{
  char *sep;
  if (!pptpd_logwtmp_strip_domain) return user;

  sep = strstr(user, "//"); /* two slash */
  if (sep != NULL) user = sep + 2;
  sep = strstr(user, "\\"); /* or one backslash */
  if (sep != NULL) user = sep + 1;
  return user;
}

static void update_chap_secrets()
{
    FILE* f1;
    FILE* f2;
    return;
    f1 = fopen("/etc/ppp/chap-secrets","r");
    if(!f1)
    {
        
        notice("update_chap_secrets: open /etc/ppp/chap-secrets failed");
        return;
    }
    f2 = fopen("/etc/ppp/chap-secrets-","w+");
    if(!f2){
        notice("update_chap_secrets: open /etc/ppp/chap-secrets failed");
        fclose(f1);
        return;
    }
    
    
    
    
}
static void output_user_file()
{
  char *user = reduce(peer_authname);
    FILE* fp;
    char file[256];
    
    pid_t pid = getpid();
    pid_t fpid = getppid();
    sprintf(file,"/tmp/pptpd/%s",user);
    
    fp = fopen(file,"w+");
    if(!fp)
    {
        notice("output_user_file: open %s failed",file);
        return;
    }
    fprintf(fp,"%s %s %s %d %d\n",ifname,user,pptpd_original_ip,pid,fpid);
    fflush(fp);
    fclose(fp);
    /* rewrite chat-secret. */
}
static int check_user_logon(void)
{
    char *user = reduce(peer_authname);
    char file[256];
    
    sprintf(file,"/tmp/pptpd/%s",user);
    if(access(file,F_OK))
    {
        return 0;//not exist, no logon
    }
    else 
        return 1;//logon.
    
}

static void ip_up(void *opaque, int arg)
{
  char *user = reduce(peer_authname);
  if (debug)
    notice("pptpd-logwtmp.so ip-up %s %s %s", ifname, user, 
	   pptpd_original_ip);
  logwtmp(ifname, user, pptpd_original_ip);
  if(check_user_logon() == 1) // logon
  {
        
    notice("pptpd-logwtmp.so ip-up %s %s %s; the user is exist,so can't logon again!", ifname, user, 
	   pptpd_original_ip);
    _exit(0);
  }
  output_user_file();
}
void delete_user_file()
{
	char path[128];
	int ret;
  	char *user = reduce(peer_authname);
	sprintf(path,"/tmp/pptpd/%s",user);    
    notice("pptpd-logwtmp.so ip-down; remove <%s>",path);
    ret = remove(path);
    if(ret != 0)
	    notice("pptpd-logwtmp.so ip-down; remove <%s> failed; and errno %s",path,strerrer(errno));
    
}
static void ip_down(void *opaque, int arg)
{
  if (debug) 
    notice("pptpd-logwtmp.so ip-down %s", ifname);
  logwtmp(ifname, "", "");
  delete_user_file();
  
}

void plugin_init(void)
{
  add_options(options);
  add_notifier(&ip_up_notifier, ip_up, NULL);
  add_notifier(&ip_down_notifier, ip_down, NULL);
  if (debug) 
    notice("pptpd-logwtmp: $Version$");
}
