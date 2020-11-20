/* .pot files writing functions
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
#include <stdio.h>
#include <string.h>
#include <error.h>
#include <errno.h>

#include "potwrite.h"

static void write_pot(FILE *fp, struct oid_list *olp)
{
	int i;
        for (i = 0; i < olp->nitems; i++) {
                fprintf (fp, "msgid \"%s\"\n", olp->item[i]->num);
		fprintf (fp, "msgstr \"%s\"\n", olp->item[i]->str);
		fprintf (fp, "\n");
	}
	return;
}

void write_pot_file(const char *filename, struct oid_list *olp)
{
	FILE *fp;

	if (olp->nitems == 0)
		return;
	if (!strcmp (filename, "-")  || !strcmp (filename, "/dev/stdout")) {
		fp = stdout;
	} else {
		fp = fopen (filename, "wb");
		if (fp == NULL)
			error (EXIT_FAILURE, errno, "error while opening \"%s\" for writing", filename);
	}
	write_pot(fp, olp);
	if (fp != stdout)
		fclose (fp);
	return;
}

