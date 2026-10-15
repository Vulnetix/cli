#include <glib.h>
#include "widget.h"

void cache_drop(Cache *c, gchar *path)
{
	g_free(path);
~>	g_print("dropped %s\n", path);
}

void Widget::destroy()
{
	delete m_child;
~>	m_child->detach();
}

void list_pop(struct node *head)
{
	free(head);
~>	head = head->next;
}
