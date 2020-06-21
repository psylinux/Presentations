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
#include <dirent.h>
#include <fcntl.h>
#include <stropts.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/un.h>

#include <locale.h>
#include <libintl.h>
#define _(x) gettext(x)

#include <gtk/gtk.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <stropts.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/un.h>

#include <locale.h>
#include <libintl.h>
#define _(x) gettext(x)

#include <gtk/gtk.h>

#include <gpe/init.h>
#include <gpe/errorbox.h>
#include <gpe/spacing.h>
#include <gpe/pixmaps.h>
#include <gpe/gpehelp.h>

#include "backend.h" /* communication and suid root backend */
#include "interface.h"
#include "main.h"
#include "editrule.h"

#define N_(x) (x)

#define MI_FILE             1
#define MI_OPEN             2
#define MI_SAVE             3
#define MI_INFO	            4
#define MI_RULES_APPLY      5
#define MI_ADD				6
#define MI_DELETE			7
#define MI_EDIT				8

#define HELPMESSAGE "Fenix Firewall\nVersion " VERSION \
		"\nFenix Firewall\n\nMarcos Azevedo (a.k.a psylinux)\nmarcos@digitalsec.com.br"

#define NOHELPMESSAGE N_("Displaying help failed.")

/* --- module global variables --- */


static rule_t *rule_info = NULL;
static int rule_count = 0;

int sock;
static pkcommand_t running_command = CMD_NONE;
static int rules_altered = 0;

/* --- global widgets --- */
static GtkWidget *notebook;
static GtkWidget *treeview;
static GtkTreeStore *store = NULL;
static GtkWidget *bApply, *bAdd, *bRemove, *bEdit;
static GtkWidget *miLoad, *miSave, *miApply;
static GtkWidget *mMain;
GtkWidget *fMain;


/* some forwards */
gboolean get_pending_messages ();
void create_fMain (void);
void on_about_clicked (GtkWidget * w);
void on_help_clicked (GtkWidget * w);
void on_apply_clicked (GtkWidget * w);
void on_load_clicked (GtkWidget * w);
void on_save_clicked (GtkWidget * w);
void on_info_clicked (GtkWidget * w);
void on_add_clicked (GtkWidget * w);
void on_remove_clicked (GtkWidget * w);
void on_edit_clicked (GtkWidget * w);
void on_rules_apply_clicked (GtkWidget * w);
void update_tree(void);


static GtkItemFactoryEntry mMain_items[] = {
  { N_("/_File"),         NULL,         NULL, MI_FILE, "<Branch>" },
  { N_("/File/_Open"), "", on_load_clicked, MI_OPEN, "<StockItem>", GTK_STOCK_OPEN},
  { N_("/File/_Save"), "", on_save_clicked, MI_SAVE, "<StockItem>", GTK_STOCK_SAVE},
  { N_("/_File/s1"), NULL , NULL,    0, "<Separator>"},
  { N_("/File/_Close"),  NULL, do_safe_exit, 0, "<StockItem>", GTK_STOCK_QUIT },
  { N_("/_Rules"),         NULL,         NULL, 0, "<Branch>" },
  { N_("/Rules/_Add"), "", on_add_clicked, MI_ADD , "<StockItem>", GTK_STOCK_ADD},
  { N_("/Rules/_Edit"), "", on_add_clicked, MI_ADD , "<StockItem>", GTK_STOCK_PROPERTIES},
  { N_("/Rules/_Delete"), "", on_remove_clicked, MI_DELETE , "<StockItem>", GTK_STOCK_DELETE},
  { N_("/Rules/_Info"), "", on_info_clicked, MI_INFO , "<Item>"},
  { N_("/Rules/s2"), NULL , NULL,    0, "<Separator>"},
  { N_("/Rules/_Apply"), "", on_rules_apply_clicked, MI_RULES_APPLY, "<StockItem>", GTK_STOCK_APPLY},
  { N_("/_Help"),         NULL, NULL,           0, "<Branch>" },
  { N_("/_Help/Index"),   NULL, on_help_clicked,    0, "<StockItem>",GTK_STOCK_HELP },
  { N_("/_Help/About"),   NULL, on_about_clicked,    0, "<Item>" },
};

int mMain_items_count = sizeof(mMain_items) / sizeof(GtkItemFactoryEntry);


struct gpe_icon my_icons[] = {
  { "exit" },
  { "icon", PREFIX "/share/pixmaps/fenix-firewall.png" },
  { NULL, NULL }
};



/* dialogs */

void
show_message(GtkMessageType type, char* message)
{
	GtkWidget* dialog;
	
	dialog = gtk_message_dialog_new (GTK_WINDOW(fMain),
					 GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
					 type,
					 GTK_BUTTONS_OK,
					 message);
	gtk_dialog_run (GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}


/* message send and receive */

static void
send_message (pkcontent_t ctype, pkcommand_t command, rule_t *rule)
{
	pkmessage_t msg;

	msg.type = PK_BACK;
	msg.ctype = ctype;
	
	/* handle commands */
	if (msg.ctype == PK_COMMAND)
	{
		running_command = command;
		switch (command)
		{
			default:
			break;
		}
	}
	msg.content.tb.command = command;
	if (rule)
		msg.content.tb.rule = *rule;
	if (write (sock, (void *) &msg, sizeof (pkmessage_t)) < 0)
	{
		perror ("ERR: sending data to backend");
	}
}

/* i'm sure there is a cleverer solution... */
void 
wait_command_finish()
{
	while (running_command != CMD_NONE)
	{
		gtk_main_iteration();
		gtk_main_iteration();
		usleep(100000);
		get_pending_messages();
	}
}


/* --- local intelligence --- */


static void
do_shutdown(void)
{
	send_message(PK_COMMAND, CMD_SHUTDOWN, NULL);
	wait_command_finish();
}

static char 
*get_color(rule_t *rule)
{
	if (!rule->status)
		return C_DISABLED;
	if (rule->is_policy) 
		return C_POLICY;
	return C_RULE;
}

/* check if a name already exists and change if necessary */
static void
rule_check_name(rule_t *rule)
{
	int i,j;
	gboolean needchange = FALSE;
	gchar *rname; 
	
	for (i=0;i<rule_count;i++)
		if ((rule != &rule_info[i]) && (!strcmp(rule->name, rule_info[i].name)))
		{
			needchange = TRUE;
			break;
		}
		
	j = 1;
	while (needchange)
	{
		j++;
		rname = g_strdup_printf("%s (%i)",rule->name,j);
		needchange = FALSE;
		
		for (i=0;i<rule_count;i++)
			if (!strcmp(rname, rule_info[i].name))
			{
				needchange = TRUE;
				break;
			}
		if (!needchange)
			snprintf(rule->name,254,"%s",rname);
		g_free(rname);
	}
}


/* add to local rule repository */
static void
do_rule_add(rule_t *rule)
{
	rule_count++;
	rule_info = realloc(rule_info,rule_count*sizeof(rule_t));
	rule_info[rule_count-1] = *rule;
}


/* adds hardcoded default policies/rules to empty ruleset */
static void
add_default_policies()
{
	if (rule_count) 
		return;
	
	rule_count++;
	rule_info = realloc(rule_info,rule_count*sizeof(rule_t));
	memset(&rule_info[rule_count-1],0,sizeof(rule_t));
	snprintf(rule_info[rule_count-1].name,254,"%s",_("Drop all incoming traffic"));
	rule_info[rule_count-1].status = 1;
	rule_info[rule_count-1].target = TARGET_DROP;
	rule_info[rule_count-1].protocol = PROT_ALL;
	rule_info[rule_count-1].chain = CHAIN_INPUT;
	rule_info[rule_count-1].d_port = 0;
	rule_info[rule_count-1].s_port = 0;
	rule_info[rule_count-1].is_policy = TRUE;
	send_message(PK_COMMAND,CMD_ADD,&rule_info[rule_count-1]);
	wait_command_finish();
	rule_count++;
	rule_info = realloc(rule_info,rule_count*sizeof(rule_t));
	memset(&rule_info[rule_count-1],0,sizeof(rule_t));
	snprintf(rule_info[rule_count-1].name,254,"%s",_("Allow SSH"));
	rule_info[rule_count-1].status = 1;
	rule_info[rule_count-1].target = TARGET_ACCEPT;
	rule_info[rule_count-1].protocol = PROT_TCP;
	rule_info[rule_count-1].chain = CHAIN_INPUT;
	rule_info[rule_count-1].d_port = 22;
	rule_info[rule_count-1].s_port = 0;
	rule_info[rule_count-1].is_policy = FALSE;
	send_message(PK_COMMAND,CMD_ADD,&rule_info[rule_count-1]);
	wait_command_finish();
	
	rule_count++;
	rule_info = realloc(rule_info,rule_count*sizeof(rule_t));
	memset(&rule_info[rule_count-1],0,sizeof(rule_t));
	snprintf(rule_info[rule_count-1].name,254,"%s",_("Allow established connections"));
	rule_info[rule_count-1].status = 1;
	rule_info[rule_count-1].target = TARGET_ACCEPT;
	rule_info[rule_count-1].protocol = PROT_ALL;
	rule_info[rule_count-1].chain = CHAIN_INPUT;
	rule_info[rule_count-1].d_port = 0;
	rule_info[rule_count-1].s_port = 0;
	rule_info[rule_count-1].state = STATE_ESTABLISHED | STATE_RELATED;
	rule_info[rule_count-1].is_policy = FALSE;
	send_message(PK_COMMAND,CMD_ADD,&rule_info[rule_count-1]);
	wait_command_finish();
	
	rule_count++;
	rule_info = realloc(rule_info,rule_count*sizeof(rule_t));
	memset(&rule_info[rule_count-1],0,sizeof(rule_t));
	snprintf(rule_info[rule_count-1].name,254,"%s",_("Allow outgoing traffic"));
	rule_info[rule_count-1].status = 1;
	rule_info[rule_count-1].target = TARGET_ACCEPT;
	rule_info[rule_count-1].protocol = PROT_ALL;
	rule_info[rule_count-1].chain = CHAIN_OUTPUT;
	rule_info[rule_count-1].d_port = 0;
	rule_info[rule_count-1].s_port = 0;
	rule_info[rule_count-1].is_policy = TRUE;
	send_message(PK_COMMAND,CMD_ADD,&rule_info[rule_count-1]);
	wait_command_finish();
}

void 
on_load_clicked (GtkWidget * w)
{
	GtkWidget *dialog;
	
	if (rules_altered)
	{		
		dialog = gtk_message_dialog_new (GTK_WINDOW (fMain),
					 GTK_DIALOG_DESTROY_WITH_PARENT,
					 GTK_MESSAGE_QUESTION,
					 GTK_BUTTONS_YES_NO,
					 _("Configuration was changed.\n"\
					 "Really restore last saved state?"));
		if (gtk_dialog_run(GTK_DIALOG(dialog)) != GTK_RESPONSE_YES)
		{
			gtk_widget_destroy(dialog);	
			return;
		}
		else
		{
			gtk_widget_destroy(dialog);
		}
	}
			
	/* do it */
	g_free(rule_info);
	rule_info = NULL;
	rule_count = 0;
	send_message(PK_COMMAND,CMD_LOAD, NULL);
	wait_command_finish();
	rules_altered = FALSE;
	update_tree();
}


void 
on_save_clicked (GtkWidget * w)
{
	send_message(PK_COMMAND,CMD_SAVE, NULL);
	wait_command_finish();
	show_message(GTK_MESSAGE_INFO,_("Saved current settings."));
	rules_altered = FALSE;
}


void 
on_info_clicked (GtkWidget * w)
{
}


void
on_add_clicked (GtkWidget * w)
{
	rule_t *newrule;
	
	newrule = edit_rule(NULL); /* returns up to date rule or NULL on abort */
	
	if (newrule != NULL) 
	{
		rule_check_name(newrule);
		newrule->status = 1;
		do_rule_add(newrule);
		send_message(PK_COMMAND,CMD_ADD,newrule);
		g_free(newrule);
		update_tree();
		rules_altered = TRUE;
	}
}


void
on_edit_clicked (GtkWidget * w)
{
	rule_t *arule;
	GtkTreeSelection *selection;
	GtkTreeIter iter;

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW(treeview));
	if (gtk_tree_selection_get_selected (selection, NULL, &iter) == FALSE) 
		return;
	gtk_tree_model_get (GTK_TREE_MODEL (store), &iter, COL_DATA, &arule, -1);
	
	arule = edit_rule(arule); /* returns up to date rule or NULL on abort */
	
	if (arule != NULL)
	{
		/* check new name */
		if (strcmp(arule->name,arule->oldname))
			rule_check_name(arule);
		send_message(PK_COMMAND,CMD_CHANGE,arule); /* tell backend */
		wait_command_finish();
		update_tree();
		rules_altered = TRUE;
	}
}


void
on_remove_clicked (GtkWidget * w)
{
	rule_t *arule;
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	int i,j;

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW(treeview));
	if (gtk_tree_selection_get_selected (selection, NULL, &iter) == FALSE) 
		return;
	gtk_tree_model_get (GTK_TREE_MODEL (store), &iter, COL_DATA, &arule, -1);
	for (i=0;i<rule_count;i++)
		if (&rule_info[i] == arule)
		{
			send_message(PK_COMMAND,CMD_REMOVE,arule);
			wait_command_finish();
			rule_count--;
			for (j=i;j<rule_count;j++)
				rule_info[j] = rule_info[j+1];
			break;
		}
	rules_altered = TRUE;
	update_tree();
}


void 
on_rules_apply_clicked (GtkWidget * w)
{
	send_message(PK_COMMAND,CMD_SET,NULL);
}


void
update_tree(void)
{
	int i;
	GtkTreeIter iter;


#warning improve this
	gtk_tree_store_clear(GTK_TREE_STORE(store));
	
	for (i=0;i<rule_count;i++)
	{
		gtk_tree_store_append (store, &iter, NULL);
		gtk_tree_store_set (store, &iter,
		    COL_NAME, rule_info[i].name,
			COL_ACTIVE, rule_info[i].status,
			COL_COLOR, get_color(&rule_info[i]),
			COL_DATA, &rule_info[i],
	    	-1);
	}
}


void
on_about_clicked (GtkWidget * w)
{
	show_message(GTK_MESSAGE_INFO,HELPMESSAGE);
}


void
on_help_clicked (GtkWidget * w)
{
	if (gpe_show_help("fenix-firewall",NULL))
		show_message(GTK_MESSAGE_ERROR,NOHELPMESSAGE);
}


void
change_network_control (GtkWidget * w)
{
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w)))
		send_message(PK_COMMAND,CMD_CFG_LOAD,NULL);
	else
		send_message(PK_COMMAND,CMD_CFG_DONTLOAD,NULL);
}


gboolean
get_network_control (void)
{
	gboolean result;
	
	if (!access(LOADRULES_MARK,F_OK))
		result = TRUE;
	else
		result = FALSE;
	
	return result;
}


void do_message_dlg(int type,char *msg)
{
	GtkWidget *dialog;
	
	dialog = gtk_message_dialog_new (GTK_WINDOW (fMain),
					 GTK_DIALOG_DESTROY_WITH_PARENT,
					 type,
					 GTK_BUTTONS_CLOSE,
					 msg);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);	
}


void do_end_command()
{
    gtk_widget_set_sensitive(miLoad,TRUE);
    gtk_widget_set_sensitive(miSave,TRUE);
    gtk_widget_set_sensitive(miApply,TRUE);
    gtk_widget_set_sensitive(bApply,TRUE);
	if (running_command == CMD_ADD) 
		update_tree();
	running_command = CMD_NONE;
}


void do_safe_exit()
{
	GtkWidget *dialog;

	if (rules_altered)
	{		
		dialog = gtk_message_dialog_new (GTK_WINDOW (fMain),
					 GTK_DIALOG_DESTROY_WITH_PARENT,
					 GTK_MESSAGE_QUESTION,
					 GTK_BUTTONS_YES_NO,
					 _("Configuration was changed.\nReally exit?"));
		if (gtk_dialog_run(GTK_DIALOG(dialog)) != GTK_RESPONSE_YES)
		{
			gtk_widget_destroy(dialog);	
			return;
		}
		else
		{
			gtk_widget_destroy(dialog);
		}
	}
	do_shutdown();
	gtk_main_quit();
}


gboolean
get_pending_messages ()
{
	static pkmessage_t msg;
	struct pollfd pfd[1];
	pfd[0].fd = sock;
	pfd[0].events = (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI);
	while (poll (pfd, 1, 0) > 0)
	{
		if ((pfd[0].revents & POLLERR) || (pfd[0].revents & POLLHUP))
		{
			perror ("ERR: connection lost: ");
			do_message_dlg(GTK_MESSAGE_ERROR,_("Backend failure, cannot continue."));
			close(sock);
			exit(1);
		}
		if (read (sock, (void *) &msg, sizeof (pkmessage_t)) < 0)
		{
			perror ("ERR: receiving data packet");
			close (sock);
			do_message_dlg(GTK_MESSAGE_ERROR,_("Communication error, cannot continue."));
			exit (1);
		}
		else
		if (msg.type == PK_FRONT)
		{
			switch (msg.ctype)
			{
				case PK_FINISHED:
#ifdef DEBUG				
				printf("finished\n");
#endif			
				do_end_command();
				break;
				case PK_RULE:
					printf("got rule\n");
					do_rule_add(&msg.content.tf.rule);
				break;
			default:
				break;
			}
		}
	}

	return TRUE;
}


/* frontend main part, non-suid process*/
int
mainloop (int argc, char *argv[])
{
	struct sockaddr_un name;
	
	sleep(1); /* wait for second process to initialize */
	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, PACKAGE_LOCALE_DIR);
	bind_textdomain_codeset (PACKAGE, "UTF-8");
	textdomain (PACKAGE);
	signal (SIGINT, do_safe_exit);
	signal (SIGTERM, do_safe_exit);
 	
	/* Create socket from which to read. */
	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
		perror ("ERR: opening datagram socket");
		exit (1);
	}

	/* Create name. */
	name.sun_family = AF_UNIX;
	strcpy (name.sun_path, PK_SOCKET);
	if (connect (sock, (struct sockaddr *) &name, SUN_LEN (&name)))
	{
		perror ("ERR: connecting to socket");
		exit (1);
	}

	if (gpe_application_init (&argc, &argv) == FALSE)
		exit (1);

	if (gpe_load_icons (my_icons) == FALSE)
		exit (1);

	create_fMain ();
	
	gtk_widget_show (fMain);
 
	gtk_timeout_add(500,get_pending_messages,NULL);
	
	/* get rules list */
	send_message(PK_COMMAND,CMD_LOAD,NULL);
	wait_command_finish();
	/* no rules? add default */
	if (rule_count == 0) 
		add_default_policies();
	update_tree();
	/* activate current rules */
	send_message(PK_COMMAND,CMD_SET,NULL);
	wait_command_finish();
	
	gtk_main ();

	close (sock);

	return 0;
}

/*
gboolean   
tv_row_clicked(GtkTreeView *treeview, GtkTreePath *arg1, 
	GtkTreeViewColumn *arg2, gpointer user_data)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	int status;

	selection = gtk_tree_view_get_selection (treeview);
	if (gtk_tree_selection_get_selected (selection, NULL, &iter) == FALSE) 
		return FALSE;
	gtk_tree_model_get (GTK_TREE_MODEL (store), &iter, COL_ACTIVE, &status, -1);
	status = !status;
	gtk_tree_store_set (GTK_TREE_STORE (store), &iter, COL_ACTIVE, status, -1);
	return TRUE;
}
*/

static void
list_toggle_inst (GtkCellRendererToggle * cellrenderertoggle,
		  gchar * path_str, gpointer model_data)
{
	GtkTreeIter iter;
	GtkTreePath *path = gtk_tree_path_new_from_string (path_str);
	int status;
	rule_t *rdat;
	
	/* get toggled iter and values */
	gtk_tree_model_get_iter (GTK_TREE_MODEL(store), &iter, path);
	gtk_tree_model_get (GTK_TREE_MODEL(store), &iter, 
		COL_ACTIVE, &status, COL_DATA, &rdat, -1);
	
	/* invert displayed value */
	status ^= 1;
	rdat->status = status;
	
	/* write values */
	gtk_tree_store_set (GTK_TREE_STORE(store), &iter, 
                      COL_ACTIVE,status,
                      COL_COLOR,get_color(rdat),-1);
	
	/* clean up */
	gtk_tree_path_free (path);
	
	rules_altered = TRUE;
	send_message(PK_COMMAND,CMD_CHANGE,rdat);
	wait_command_finish();
}


/* create menus from description */
GtkWidget *
create_mMain(GtkWidget  *window)
{
	GtkItemFactory *itemfactory;
	GtkAccelGroup *accelgroup;

	accelgroup = gtk_accel_group_new ();

	itemfactory = gtk_item_factory_new (GTK_TYPE_MENU_BAR, "<main>",
                                       accelgroup);
	gtk_item_factory_create_items (itemfactory, mMain_items_count, 
		mMain_items, NULL);
	gtk_window_add_accel_group (GTK_WINDOW (window), accelgroup);

	miApply = gtk_item_factory_get_item_by_action(itemfactory, MI_RULES_APPLY);
	miLoad = gtk_item_factory_get_item_by_action(itemfactory, MI_OPEN);
	miSave = gtk_item_factory_get_item_by_action(itemfactory, MI_SAVE);
	
	return (gtk_item_factory_get_widget (itemfactory, "<main>"));
}



/* --- create mainform --- */

void
create_fMain (void)
{
  GtkWidget *vbox;
  GtkWidget *cur;
  GtkWidget *toolbar;
  GtkWidget *pw;
  GtkTooltips *tooltips;
  GtkCellRenderer *renderer;
  GtkTreeViewColumn *column;
  char *tmp;
  	int size_x, size_y;

	/* init tree storage stuff */
	store = gtk_tree_store_new (N_COLUMNS,
				    G_TYPE_BOOLEAN,
				    G_TYPE_STRING,
					G_TYPE_STRING,
				    G_TYPE_POINTER
	);

  /* main window */
  size_x = gdk_screen_width() / 2;
  size_y = gdk_screen_height() * 2 / 3;  
  if (size_x < 240) size_x = 240;
  if (size_y < 320) size_y = 320;
  fMain = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title (GTK_WINDOW (fMain), _("Fenix Firewall"));
  gtk_window_set_default_size (GTK_WINDOW (fMain), size_x, size_y);
  gpe_set_window_icon(fMain, "icon");

  vbox = gtk_vbox_new(FALSE,0);
  gtk_container_add(GTK_CONTAINER(fMain),vbox);
	
  tooltips = gtk_tooltips_new ();
  
  /* main menu */ 
  mMain = create_mMain(fMain);
  gtk_box_pack_start(GTK_BOX(vbox),mMain,FALSE,TRUE,0);
  
  /* toolbar */
	
  toolbar = gtk_toolbar_new ();
  gtk_toolbar_set_orientation (GTK_TOOLBAR (toolbar),
			       GTK_ORIENTATION_HORIZONTAL);

  bApply = gtk_toolbar_insert_stock (GTK_TOOLBAR (toolbar), GTK_STOCK_APPLY,
			   _("Apply rules"), _("Apply rules"),
			   (GtkSignalFunc) on_rules_apply_clicked , NULL, -1);
			   
  bAdd = gtk_toolbar_insert_stock (GTK_TOOLBAR (toolbar), GTK_STOCK_ADD,
			   _("Add rule"), _("Add rule"),
			   (GtkSignalFunc) on_add_clicked , NULL, -1);
			   
  bRemove = gtk_toolbar_insert_stock (GTK_TOOLBAR (toolbar), GTK_STOCK_REMOVE,
			   _("Remove rule"), _("Remove Rule"),
			   (GtkSignalFunc) on_remove_clicked , NULL, -1);
			   
  bEdit = gtk_toolbar_insert_stock (GTK_TOOLBAR (toolbar), GTK_STOCK_PROPERTIES,
			   _("Edit rule"), _("Edit Rule"),
			   (GtkSignalFunc) on_edit_clicked , NULL, -1);
			   
  gtk_toolbar_append_space(GTK_TOOLBAR(toolbar));
  
  pw = gtk_image_new_from_pixbuf(gpe_find_icon ("exit"));
  gtk_toolbar_append_item (GTK_TOOLBAR (toolbar), _("Exit"),
			   _("Close application"), _("Close application"), pw,
			   (GtkSignalFunc) do_safe_exit, NULL);
			   
  gtk_box_pack_start(GTK_BOX(vbox),toolbar,FALSE,TRUE,0);

  /* notebook */
  
  notebook = gtk_notebook_new();	
  gtk_box_pack_start(GTK_BOX(vbox),notebook,TRUE,TRUE,0);
	
  gtk_object_set_data(GTK_OBJECT(notebook),"tooltips",tooltips);
  
  /* installed tab */	
  vbox = gtk_vbox_new(FALSE,gpe_get_boxspacing());

  cur = gtk_label_new(_("Rules"));
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook),vbox,cur);

  cur = gtk_label_new(NULL);
  gtk_misc_set_alignment(GTK_MISC(cur),0.0,0.5);
  tmp = g_strdup_printf("<b>%s</b>",_("Filter rules"));
  gtk_label_set_markup(GTK_LABEL(cur),tmp);
  free(tmp);
  gtk_box_pack_start(GTK_BOX(vbox),cur,FALSE,TRUE,0);	
	
  cur = gtk_scrolled_window_new(NULL,NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(cur),
  	GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(cur), GTK_SHADOW_IN);
  gtk_box_pack_start(GTK_BOX(vbox), cur, TRUE, TRUE, 0);	

  /* rules tree */
  treeview = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));
  gtk_tree_view_set_reorderable(GTK_TREE_VIEW(treeview),TRUE);
  gtk_tree_view_set_rules_hint (GTK_TREE_VIEW(treeview),TRUE);
  gtk_container_add(GTK_CONTAINER(cur),treeview);	
  
/*	g_signal_connect_after (G_OBJECT (treeview), "cursor-changed",
			  G_CALLBACK (tv_row_clicked), NULL);
*/
	renderer = gtk_cell_renderer_toggle_new ();
	gtk_cell_renderer_toggle_set_radio(GTK_CELL_RENDERER_TOGGLE(renderer),FALSE);
	g_signal_connect (G_OBJECT (renderer), "toggled",
					  G_CALLBACK (list_toggle_inst), store);
	column = gtk_tree_view_column_new_with_attributes (_("Active"),
							   renderer,
							   "active",
							   COL_ACTIVE,
							   "cell-background",
							   COL_COLOR,
							   NULL);
	gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (_("Name"),
							   renderer,
							   "text",
							   COL_NAME,
							   "background",
							   COL_COLOR,
							   NULL);
	gtk_tree_view_column_set_resizable(GTK_TREE_VIEW_COLUMN(column),TRUE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (treeview), column);

  
  /* confguration tab */
  vbox = gtk_vbox_new(FALSE,gpe_get_boxspacing());

  cur = gtk_label_new(_("Configuration"));
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook),vbox,cur);
  cur = gtk_label_new(NULL);
  tmp = g_strdup_printf("<b>%s</b>",_("Network Security Configuration"));
  gtk_label_set_markup(GTK_LABEL(cur),tmp);
  gtk_misc_set_alignment(GTK_MISC(cur),0.0,0.5);
  free(tmp);
  gtk_box_pack_start(GTK_BOX(vbox),cur,FALSE,TRUE,0);	
  
  cur = gtk_check_button_new_with_label(_("Start network control on login"));
  gtk_box_pack_start(GTK_BOX(vbox),cur,FALSE,TRUE,0);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cur),get_network_control());
  g_signal_connect_after (G_OBJECT (cur), "toggled",
			  G_CALLBACK (change_network_control), NULL);
  
  g_signal_connect(G_OBJECT (fMain),"destroy",gtk_main_quit,NULL);
  
  gtk_widget_show_all(fMain);
}
