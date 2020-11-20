/* Utility for parsing CertUtil.ext output
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

static void proc_oid(const char *oid, const char *name)
{
	FILE *file;
        char *line = NULL, *s;
        size_t n;
        ssize_t read;

	if ((file = fopen(name, "r")) == NULL) {
                fprintf (stderr, "Failed to open %s file\n", name);
                exit(EXIT_FAILURE);
        }

	while ((read = getline(&line, &n, file)) != -1) {
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
		s = strstr(line, oid);
		if (s == NULL)
			continue;
		if (s - line != 35)
			continue;
		if (s[strlen(oid)] == '\0')
			continue;
		if (s[strlen(oid)] != ' ')
			continue;
		printf ("msgid \"%s\"\n", oid);
		printf ("msgstr \"%s\"\n", s + strlen(oid) + 1);
		printf ("\n");
		break;
	}
	if (line)
                free (line);

	fclose (file);
	return;
}

int main(int argc, char *argv[])
{
	FILE *file;
	char *line = NULL;
        size_t n;
        ssize_t read;

	if ((file = fopen(argv[1], "r")) == NULL) {
		fprintf (stderr, "Failed to open %s file\n", argv[1]);
                exit(EXIT_FAILURE);
	}

	while ((read = getline(&line, &n, file)) != -1) {
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
		proc_oid (line, argv[2]);
	}
	if (line)
                free (line);
	fclose (file);
	return EXIT_SUCCESS;
}
