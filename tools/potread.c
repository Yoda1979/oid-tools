/* .pot files reading functions
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
#include <string.h>
#include <stdio.h>
#include <error.h>
#include <errno.h>
#include <iconv.h>

#include "potlib.h"
#include "potread.h"

void read_pot_file(const char *filename, struct oid_list *olp, bool str_check)
{
	FILE *fp;
        char *line = NULL, *s;
        size_t n;
        ssize_t read;
	char *oidnum;

	if (!strcmp (filename, "-")  || !strcmp (filename, "/dev/stdin")) {
		fp = stdin;
	} else {
		fp = fopen (filename, "r");
		if (fp == NULL)
			error (EXIT_FAILURE, errno, "error while opening \"%s\" for reading", filename);
	}

        while ((read = getline(&line, &n, fp)) != -1) {
                if (line[0] == '\n')
                        continue;
                if (line[read - 1] == '\n') {
                        line[read - 1] = '\0';
                } else {
                        char *buf;
                        buf = malloc(read + 1);
                        if (buf == NULL)
                                continue;
                        memcpy (buf, line, read);
                        buf[read] = '\0';
                        free (line);
                        line = buf;
                        n++;
                }
		if (!strncmp(line, "msgid", strlen("msgid"))) {
                	s = strrchr(line, '\"');
                	if (s == NULL)
                	        error (EXIT_FAILURE, 0, "Failed to strrchr %s file\n", filename);
                	*s = '\0';
                	s = strchr(line, '\"');
                	if (s == NULL)
                	        error (EXIT_FAILURE, 0, "Failed to strchr %s file\n", filename);
			oidnum = strdup(s + 1);
			if (oidnum == NULL)
				error (EXIT_FAILURE, 0, "Error line: %s\n", line);
			if (oidval(oidnum)) {
				free (oidnum);
				error (EXIT_FAILURE, 0, "Bad OID: %s\n", line);
			}
		} else if (!strncmp(line, "msgstr", strlen("msgstr"))) {
                        if (oidnum == NULL)
                                error (EXIT_FAILURE, 0, "Error line 6: %s\n", line);
                	s = strrchr(line, '\"');
                	if (s == NULL)
                	        error (EXIT_FAILURE, 0, "Failed to strrchr %s file\n", filename);
                	*s = '\0';
                	s = strchr(line, '\"');
                	if (s == NULL)
                	        error (EXIT_FAILURE, 0, "Failed to strchr %s file\n", filename);
			oid_list_append(olp, oidnum, s + 1, str_check);
                        free (oidnum);
                        oidnum = NULL;
		} else {
                        error (EXIT_FAILURE, 0, "Error line: %s\n", line);
                }
        }
        if (line)
                free (line);

	if (fp != stdin)
		fclose (fp);
	return;
}
