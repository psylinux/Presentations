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

#include <locale.h>
#include <libintl.h>
#define _(x) gettext(x)

#include <gtk/gtk.h>
#include <gpe/spacing.h>

#include "backend.h"
#include "interface.h"

typedef struct
{
	const char* strval;
	int nval;
}
val_t;

#define VAL_ACCEPT  "accept"
#define VAL_DROP "drop"
#define VAL_REJECT "reject"
#define VAL_INPUT "incoming"
#define VAL_OUTPUT "outgoing"
#define VAL_FORWARD "forwarded"
#define VAL_TCP "TCP"
#define VAL_UDP "UDP"
#define VAL_ICMP "ICMP"
#define VAL_ALL "<all>"

static const val_t val_chain[] = {{ VAL_INPUT, CHAIN_INPUT}, {VAL_OUTPUT, CHAIN_OUTPUT}, {VAL_FORWARD, CHAIN_FORWARD}};
int n_chain = sizeof(val_chain)/sizeof(val_t);
static const val_t val_target[] = {{ VAL_ACCEPT, TARGET_ACCEPT}, {VAL_DROP, TARGET_DROP}, {VAL_REJECT, TARGET_REJECT}};
int n_target = sizeof(val_target)/sizeof(val_t);
static const val_t val_protocol[] = {{ VAL_TCP, PROT_TCP}, {VAL_UDP, PROT_UDP}, {VAL_ICMP, PROT_ICMP}, {VAL_ALL, PROT_ALL}};
int n_protocol = sizeof(val_protocol)/sizeof(val_t);

static GtkWidget *edit_dialog;
static GtkWidget *cbChain, *cbTarget, *cbProtocol;
static GtkWidget *eName, *eSPort, *eDPort;


void 
update_widgets(GtkWidget* sender)
{
	char *prot = 
		gtk_editable_get_chars(GTK_EDITABLE(GTK_COMBO(cbProtocol)->entry),0,-1);
	if ((!strcmp(prot,VAL_TCP)) || (!strcmp(prot,VAL_UDP)))
	{
		gtk_widget_set_sensitive(GTK_WIDGET(eSPort),TRUE);
		gtk_widget_set_sensitive(GTK_WIDGET(eDPort),TRUE);
	}
	else
	{
		gtk_widget_set_sensitive(GTK_WIDGET(eSPort),FALSE);
		gtk_widget_set_sensitive(GTK_WIDGET(eDPort),FALSE);
	}
}


static GtkWidget*
create_dialog()
{
	GtkWidget *dialog, *label, *table;
	gchar *text;
	GList *slTarget = NULL;
	GList *slChain = NULL;
	GList *slProtocol = NULL;
	
	slTarget = g_list_append(slTarget,VAL_ACCEPT);
	slTarget = g_list_append(slTarget,VAL_DROP);
	slTarget = g_list_append(slTarget,VAL_REJECT);

	slChain = g_list_append(slChain,VAL_INPUT);
	slChain = g_list_append(slChain,VAL_OUTPUT);
	slChain = g_list_append(slChain,VAL_FORWARD);
	
	slProtocol = g_list_append(slProtocol,VAL_TCP);
	slProtocol = g_list_append(slProtocol,VAL_UDP);
	slProtocol = g_list_append(slProtocol,VAL_ICMP);
	slProtocol = g_list_append(slProtocol,VAL_ALL);
	
	dialog = 
		gtk_dialog_new_with_buttons(_("Edit rule"),
	                                GTK_WINDOW(fMain),
	                                GTK_DIALOG_MODAL 
	                                | GTK_DIALOG_DESTROY_WITH_PARENT,
	                                GTK_STOCK_CANCEL,GTK_RESPONSE_CANCEL,
	                                GTK_STOCK_OK,GTK_RESPONSE_OK,
	                                NULL);
	table = gtk_table_new(4,3,FALSE);
	gtk_table_set_col_spacings(GTK_TABLE(table),gpe_get_boxspacing());
	gtk_table_set_row_spacings(GTK_TABLE(table),gpe_get_boxspacing());
	gtk_container_set_border_width(GTK_CONTAINER(table),gpe_get_border());
	
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox),table,TRUE,TRUE,0);
	
	label = gtk_label_new(NULL);
	gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
	text = g_strdup_printf("<b>%s</b>",_("Edit rule parameters"));
	gtk_label_set_markup(GTK_LABEL(label),text);
	g_free(text);
	gtk_table_attach(GTK_TABLE(table),label,0,2,0,1,GTK_FILL | GTK_EXPAND,GTK_FILL,0,0);
	
	label = gtk_label_new(_("Name"));
	gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
	gtk_table_attach(GTK_TABLE(table),label,0,1,1,2,GTK_FILL,GTK_FILL,0,0);
	
	eName = gtk_entry_new_with_max_length(254);
	gtk_table_attach(GTK_TABLE(table),eName,1,3,1,2,GTK_FILL | GTK_EXPAND,GTK_FILL,0,0);

	label = gtk_label_new(_("Direction"));
	gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
	gtk_table_attach(GTK_TABLE(table),label,0,1,2,3,GTK_FILL,GTK_FILL,0,0);
	
	cbChain = gtk_combo_new();
	gtk_combo_set_value_in_list(GTK_COMBO(cbChain),TRUE,FALSE);
	gtk_combo_set_popdown_strings(GTK_COMBO(cbChain),slChain);
	gtk_table_attach(GTK_TABLE(table),cbChain,1,3,2,3,GTK_FILL | GTK_EXPAND,GTK_FILL,0,0);
	
	label = gtk_label_new(_("Action"));
	gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
	gtk_table_attach(GTK_TABLE(table),label,0,1,3,4,GTK_FILL,GTK_FILL,0,0);
	
	cbTarget = gtk_combo_new();
	gtk_combo_set_value_in_list(GTK_COMBO(cbTarget),TRUE,FALSE);
	gtk_combo_set_popdown_strings(GTK_COMBO(cbTarget),slTarget);
	gtk_table_attach(GTK_TABLE(table),cbTarget,1,3,3,4,GTK_FILL | GTK_EXPAND,GTK_FILL,0,0);
	
	label = gtk_label_new(_("Protocol"));
	gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
	gtk_table_attach(GTK_TABLE(table),label,0,1,4,5,GTK_FILL,GTK_FILL,0,0);
	
	cbProtocol = gtk_combo_new();
	gtk_combo_set_value_in_list(GTK_COMBO(cbProtocol),TRUE,FALSE);
	gtk_combo_set_popdown_strings(GTK_COMBO(cbProtocol),slProtocol);
	gtk_table_attach(GTK_TABLE(table),cbProtocol,1,3,4,5,GTK_FILL | GTK_EXPAND,GTK_FILL,0,0);
	g_signal_connect_after(G_OBJECT(GTK_COMBO(cbProtocol)->entry),"changed",
		G_CALLBACK(update_widgets),NULL);
		
	label = gtk_label_new(_("Source port"));
	gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
	gtk_table_attach(GTK_TABLE(table),label,0,1,5,6,GTK_FILL,GTK_FILL,0,0);
	
	eSPort = gtk_entry_new_with_max_length(5);
	gtk_table_attach(GTK_TABLE(table),eSPort,1,3,5,6,GTK_FILL | GTK_EXPAND,GTK_FILL,0,0);
	
	label = gtk_label_new(_("Destination port"));
	gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
	gtk_table_attach(GTK_TABLE(table),label,0,1,6,7,GTK_FILL,GTK_FILL,0,0);
	
	eDPort = gtk_entry_new_with_max_length(5);
	gtk_table_attach(GTK_TABLE(table),eDPort,1,3,6,7,GTK_FILL | GTK_EXPAND,GTK_FILL,0,0);
	return dialog;
}


/* edit a rule, returns changed rule or NULL on abort */
rule_t*
edit_rule(rule_t *rule)
{
	int i;
	char *text;
	
	/* check if we need to allocate a new rule */
	if (rule == NULL)
	{
		rule = malloc(sizeof(rule_t));
		memset(rule,0,sizeof(rule_t));
		/* set some defaults */
		sprintf(rule->name,"%s",_("New rule"));
	}
	
	edit_dialog = create_dialog();
	
	/* fill in values */
	gtk_entry_set_text(GTK_ENTRY(eName),rule->name);
	for (i=0;i<n_chain;i++)
		if (val_chain[i].nval == rule->chain)
		{
			gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(cbChain)->entry),val_chain[i].strval);
			break;
		}
	for (i=0;i<n_target;i++)
		if (val_target[i].nval == rule->target)
		{
			gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(cbTarget)->entry),val_target[i].strval);
			break;
		}
	for (i=0;i<n_protocol;i++)
		if (val_protocol[i].nval == rule->protocol)
		{
			gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(cbProtocol)->entry),val_protocol[i].strval);
			break;
		}
		
	text = g_strdup_printf("%d",rule->s_port);
	gtk_entry_set_text(GTK_ENTRY(eSPort),text);
	g_free(text);
	text = g_strdup_printf("%d",rule->d_port);
	gtk_entry_set_text(GTK_ENTRY(eDPort),text);
	g_free(text);
	
	gtk_widget_show_all(edit_dialog);
	
	/* run dialog, get values on ok */
	if (gtk_dialog_run(GTK_DIALOG(edit_dialog)) == GTK_RESPONSE_OK)
	{
		snprintf(rule->oldname,254,"%s",rule->name);
		snprintf(rule->name,254,"%s",
			gtk_entry_get_text(GTK_ENTRY(eName)));
		text = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(cbChain)->entry));
		for (i=0;i<n_chain;i++)
			if (!strcmp(val_chain[i].strval,text))
			{
				rule->chain = val_chain[i].nval;
				break;
			}
		text = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(cbTarget)->entry));
		for (i=0;i<n_target;i++)
			if (!strcmp(val_target[i].strval,text))
			{
				rule->target = val_target[i].nval;
				break;
			}
		text = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(cbProtocol)->entry));
		for (i=0;i<n_protocol;i++)
			if (!strcmp(val_protocol[i].strval,text))
			{
				rule->protocol = val_protocol[i].nval;
				break;
			}
			
		rule->s_port = atol(gtk_entry_get_text(GTK_ENTRY(eSPort)));
		rule->d_port = atol(gtk_entry_get_text(GTK_ENTRY(eDPort)));
	
		gtk_widget_destroy(edit_dialog);
		return rule;
	}
	else
	{
		gtk_widget_destroy(edit_dialog);
		return NULL;
	}
}
