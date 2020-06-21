/*
 * fenix-firewall
 *
 * Copyright (C) 2009 DigitalSec
 * Marcos Azevedo <marcos@digitalsec.com.br>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Fenix Firewall System.
 * Module: iptables backend
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <gdk/gdk.h>

#include "backend.h"
#include "main.h"

/* module global variables */

static int sock = -1;

/* local rule repository */
static rule_t *rule_info = NULL;
static int rule_count = 0;

#define CONFIGFILE	"/etc/fenix/access.conf"
#define DEFAULT_INTERFACE "! lo"

#ifdef MACH_IPAQ
#define IPTABLES_CMD "/usr/sbin/iptables"
#else
#define IPTABLES_CMD "/sbin/iptables"
#endif

/* forwared definitions */

static void do_command (pkcommand_t command, rule_t rule);
static int wait_message ();
static void send_message (pkcontent_t ctype, rule_t *rule);


/* iptables control routines */

void 
translate_name(char *name, int set)
{
	char* ptr = name;
	if (set)
		while ((ptr = strstr(ptr," ")))
			ptr[0] = '%';
	else	
		while ((ptr = strstr(ptr,"%")))
			ptr[0] = ' ';
}

int
do_save_rules(void)
{
	FILE *cfgfile;
	int i;
	
	cfgfile = fopen(CONFIGFILE,"w");
	if (!cfgfile) 
		return -1;
	
	for (i=0;i<rule_count;i++)
	{
		translate_name(rule_info[i].name,1);
		fprintf(cfgfile,"%s %d %d %d %d %d %d %d %d\n",
		        rule_info[i].name,
	            rule_info[i].status,
	            rule_info[i].target,
	            rule_info[i].protocol,
	            rule_info[i].chain,
	            rule_info[i].d_port,
	            rule_info[i].s_port,
	            rule_info[i].state,
	            rule_info[i].is_policy);
	}
	fclose(cfgfile);
	return 0;
}


int
do_load_rules(void)
{
	FILE *cfgfile;
	int ret = 0;
	rule_t arule;
	
	cfgfile = fopen(CONFIGFILE,"r");
	if (!cfgfile) 
		return -1;
	while (ret != EOF)
	{
		ret = fscanf(cfgfile,"%254s %d %d %d %d %d %d %d %d\n",
		       (char*)arule.name,
	           &arule.status,
	           (int*)&arule.target,
	           (int*)&arule.protocol,
	           (int*)&arule.chain,
	           &arule.d_port,
	           &arule.s_port,
		       &arule.state,
	           &arule.is_policy);
		if (ret == 9)
		{
			rule_count++;
			rule_info = realloc(rule_info,rule_count*sizeof(rule_t));
			memset(&rule_info[rule_count-1],0,sizeof(rule_t));
			translate_name(arule.name,0);
			rule_info[rule_count - 1] = arule;
			send_message(PK_RULE,&rule_info[rule_count-1]);
		}
	}
	fclose(cfgfile);
	return 0;
}


void
do_clear(void)
{
	system(IPTABLES_CMD " --flush");
	g_free(rule_info);
	rule_info = NULL;
	rule_count = 0;
}


void
do_rules_apply()
{
	gchar *cmd, *portspec, *states, *tmp;
	const gchar *dir;
	const gchar *prot;
	const gchar *target;
	int i;
	
	system(IPTABLES_CMD " --flush"); /* cleans all existing iptables settings */

	for (i=0;i<rule_count;i++)
	{	
		if (rule_info[i].status) /* is rule active? */
		{
			/* prepare command */
			switch (rule_info[i].target)
			{
				case TARGET_ACCEPT:
					target = "ACCEPT";
				break;
				case TARGET_DROP:
					target = "DROP";
				break;
				default:
					target = "REJECT";
				break;
			}
			
			switch (rule_info[i].chain)
			{
				case CHAIN_FORWARD:
					dir = "FORWARD";
				break;
				case CHAIN_OUTPUT:
					dir = "OUTPUT";
				break;
				default:
					dir = "INPUT";
				break;
			}
			
			switch (rule_info[i].protocol)
			{
				case PROT_ICMP:
					prot = "-p icmp";
				break;
				case PROT_TCP :
					prot = "-p tcp";
				break;
				case PROT_UDP :
					prot = "-p udp";
				break;
				default:
					prot = "-p all";
				break;
			}
			
			states = NULL;
			if (rule_info[i].state)
			{
				tmp = g_strdup("-m state --state ");
				if (rule_info[i].state & STATE_ESTABLISHED)
				{
					states = g_strdup_printf("%s ESTABLISHED",tmp);
					tmp = states;
				}
				if (rule_info[i].state & STATE_RELATED)
				{
					if (states) 
					{
						states = g_strdup_printf("%s,RELATED",tmp);
						g_free(tmp);
					}
					else
						states = g_strdup_printf("%s RELATED",tmp);						
					tmp = states;
				}
				if (rule_info[i].state & STATE_NEW)
				{
					if (states) 
					{
						states = g_strdup_printf("%s,NEW",tmp);
						g_free(tmp);
					}
					else
						states = g_strdup_printf("%s NEW",tmp);						
					tmp = states;
				}
				if (rule_info[i].state & STATE_INVALID)
				{
					if (states) 
					{
						states = g_strdup_printf("%s,INVALID",tmp);
						g_free(tmp);
					}
					else
						states = g_strdup_printf("%s INVALID",tmp);						
					tmp = states;
				}
			}
			else
				states = g_strdup("");
			
			if (rule_info[i].s_port)
				portspec = g_strdup_printf("--sport %d",rule_info[i].s_port);
			else if (rule_info[i].d_port)
				portspec = g_strdup_printf("--dport %d",rule_info[i].d_port);
			else 
				portspec = g_strdup("");
			
			if (rule_info[i].is_policy)
				cmd = g_strdup_printf("%s %s %s %s",IPTABLES_CMD, "-P", dir, target);
			else	
				cmd = g_strdup_printf("%s %s %s %s %s %s %s %s -j %s",
								  IPTABLES_CMD, 
								  "-A", dir,
								  (rule_info[i].chain == CHAIN_OUTPUT) ? "-o" : "-i", DEFAULT_INTERFACE,
				                  states,
								  prot,
								  portspec,
								  target);
#ifdef DEBUG			
			printf("exec: %s\n",cmd);
#endif
			/* call iptables to add rule */
			system(cmd);
			
			g_free(cmd);
			g_free(portspec);
			g_free(states);
		}
	}		
}


/* add a frontend defined rule to ipchains ruleset and local storage */
static void
do_rule_add(rule_t *rule)
{
	/* add to local rule repository */
	rule_count++;
	rule_info = realloc(rule_info,rule_count*sizeof(rule_t));
	rule_info[rule_count - 1] = *rule;
}


static void
do_rule_remove(rule_t *rule)
{
	int i, j;
	
	for (i=0;i<rule_count;i++)
	{
		if (!strcmp(rule_info[i].name,rule->name))
		{
			rule_count--;
			for (j=i;j<rule_count;j++)
				rule_info[j] = rule_info[j+1];
			break;
		}
	}
}


static void
do_rule_change(rule_t *rule)
{
	int i;
	
	for (i=0;i<rule_count;i++)
	{
		if ((!strcmp(rule_info[i].name,rule->oldname)) ||
			(!strcmp(rule_info[i].name,rule->name)))
		{
			rule_info[i] = *rule;
			break;
		}
	}
}


/* message send and receive */

static void
send_message (pkcontent_t ctype, rule_t *rule)
{
	pkmessage_t msg;
	
	if (sock < 0) return; /* no connection active */
	msg.type = PK_FRONT;
	msg.ctype = ctype;
	if (rule) 
		msg.content.tf.rule = *rule;
	if (write (sock, (void *) &msg, sizeof (pkmessage_t)) < 0)
	{
		perror ("ERR sending data to frontend");
	}
}


static void
do_shutdown()
{
//	system(IPTABLES_CMD " --flush"); /* cleans all existing iptables settings */
//	system(IPTABLES_CMD " -P INPUT ACCEPT"); /* reset input policy */
}

static int
wait_message ()
{
	static pkmessage_t msg;
	struct pollfd pfd[1];
	static int retry_count = 0;

	pfd[0].fd = sock;
	pfd[0].events = (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI);
	while (poll (pfd, 1, -1) > 0)
	{
		if ((pfd[0].revents & POLLERR) || (pfd[0].revents & POLLHUP))
		{
#ifdef DEBUG
			perror ("Err: connection lost: ");
#endif		
			retry_count++;
			if (retry_count > 6) return FALSE;
			usleep(500000);
		}
		else
		{
			if (read (sock, (void *) &msg, sizeof (pkmessage_t)) < 0)
			{
	#ifdef DEBUG
				perror ("err receiving data packet");
	#endif
				close (sock);
				exit (1);
			}
			else if (msg.type == PK_BACK)
			{
				retry_count = 0;
				switch (msg.ctype)
				{
				case (PK_COMMAND):
					do_command (msg.content.tb.command, msg.content.tb.rule);
					break;
				default:
					break;
				}
			}
		} /* else */	
	} /* while */
	return TRUE;
}


static void
do_change_cfg_load(gboolean doit)
{
	int fh;
	if (doit)
	{
		if ((fh = open(LOADRULES_MARK,O_CREAT | O_RDWR | O_TRUNC)) < 0)
			perror("Cannot save setting.");
		else
			close(fh);
	}
	else
	{
		if (remove(LOADRULES_MARK) < 0)
			perror("Cannot save setting.");
	}
}


static void
do_command (pkcommand_t command, rule_t rule)
{
	switch (command)
	{
	case CMD_ADD:   /* add a rule defined by frontend */
		do_rule_add(&rule);
	break;
	case CMD_CHANGE:   
		do_rule_change(&rule);
	break;
	case CMD_REMOVE:
		do_rule_remove(&rule);
	break;
	case CMD_LOAD:  /* load ruleset from config file */
		do_clear();
		do_load_rules();
	break;
	case CMD_SAVE:
		do_save_rules();
	break;
	case CMD_CLEAR: /* clear all rules in system and storage */
		do_clear();
	break;
	case CMD_SET:
		do_rules_apply();
	break;
	case CMD_SHUTDOWN:
		do_shutdown();
	break;
	case CMD_CFG_LOAD:
		do_change_cfg_load(TRUE);
	break;
	case CMD_CFG_DONTLOAD:
		do_change_cfg_load(FALSE);
	break;
	default:
	break;
	}
	
	send_message(PK_FINISHED,NULL);
}


/* app mainloop */

int
suidloop (int csock)
{
	sock = csock;

	while (wait_message ()) ;
		
	close (sock);
	unlink (PK_SOCKET);

	return 0;
}
