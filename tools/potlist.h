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

#ifndef _POTLIST_H
#define _POTLIST_H

#include <stdbool.h>

struct oid_item {
	char *num;
	char *str;
};

struct oid_list {
	struct oid_item **item;
	size_t nitems;
	size_t nmax;
};

void oid_list_append(struct oid_list *olp, const char *oid, char *str, bool str_check);
void oid_list_free (struct oid_list *olp);
void oid_list_sort (struct oid_list *olp);

#endif
