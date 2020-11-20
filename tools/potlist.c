/* OID listing functions
   Copyright (C) 2020 Sergey V. Kostyuk

   This file was written by Sergey V. Kostyuk <kostyuk.sergey79@gmail.com>, 2020.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <error.h>

#include "xalloc.h"

#include "potlib.h"
#include "potlist.h"

void oid_list_append(struct oid_list *olp, const char *oid, char *str, bool str_check)
{
	struct oid_item *item;
	int inc = 4096, i, len;

	for (i = 0; i < olp->nitems; i++) {
		if (!strcmp(olp->item[i]->num, oid)) {
			if (str_check && strcmp(olp->item[i]->str, str)) {
				fprintf (stderr, "OID %s is inconsistent\n", oid);
				fprintf (stderr, "> %s\n", olp->item[i]->str);
				fprintf (stderr, "< %s\n", str);
				exit  (EXIT_FAILURE);
			}
			return;
		}
	}

	/** new oid **/
	if (olp->nitems + 1 > olp->nmax) {
		olp->item = xrealloc(olp->item, (olp->nmax + inc) * sizeof(struct oid_item *));
		olp->nmax += inc;
	}

	item = xmalloc(sizeof(struct oid_item));
	len = strlen(oid);
	item->num = xmalloc(len + 1);
	memcpy(item->num, oid, len);
	item->num[len] = '\0';
	if (str) {
		len = strlen(str);
		item->str = xmalloc(len + 1);
		memcpy(item->str, str, len);
		item->str[len] = '\0';
	} else {
		item->str = NULL;
	}
	olp->item[olp->nitems] = item;
	olp->nitems++;
	return;
}

void oid_list_free (struct oid_list *olp)
{
	int i;

	for (i = 0; i < olp->nitems; i++) {
		free (olp->item[i]->num);
		if (olp->item[i]->str)
			free (olp->item[i]->str);
		free (olp->item[i]);
	}
	free (olp->item);
	olp->item = NULL;
	return;
}

static int compare_cb(const void *p1, const void *p2)
{
	struct oid_item *item1, *item2;
	item1 = *((struct oid_item **)p1);
	item2 = *((struct oid_item **)p2);
	return oidcmp(item1->num, item2->num);
}

void oid_list_sort (struct oid_list *olp)
{
	qsort(olp->item, olp->nitems, sizeof(struct oid_item *), compare_cb);
}
