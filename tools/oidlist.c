/* Utility for listing OIDs in .pot files
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <error.h>

#include "closeout.h"
#include "progname.h"

#include "potread.h"
#include "potlist.h"

// AAA

struct oid_list olist  = { NULL, 0, 0 };
bool do_sort = false;

void olist_free (void)
{
	int i;

	if (olist.item == NULL)
		return;
	for (i = 0; i < olist.nitems; i++) {
		free (olist.item[i]->num);
		if (olist.item[i]->str)
			free (olist.item[i]->str);
		free (olist.item[i]);
	}
	return;
}

static struct option long_options[] = {
                        { "sort",  no_argument, 0, 's'},
			{ "help",  no_argument, 0, 'h'},
                        { 0,       0,           0,  0 }
};

static void usage (int status)
{
        if (status != EXIT_SUCCESS) {
                fprintf (stderr, "Try '%s --help' for more information.\n", program_name);
        } else {

                printf ("Usage: %s [OPTION] [FILE]...\n", program_name);
                printf ("\n");
                printf ("List OIDs in .pot files.\n");
                printf ("\n");
                printf ("Options:\n");
                printf ("-s, --sort                  sort OIDs\n");
                printf ("\n");
                printf ("Informative output:\n");
                printf ("-h, --help                  display this help and exit\n");
                printf ("\n");
        }
        exit (status);
}

static void print_oid_list(struct oid_list *olp)
{
	int i;

	for (i = 0; i < olp->nitems; i++)
		fprintf (stdout, "%s\n", olp->item[i]->num);
}

int main(int argc, char *argv[])
{
	int c;

	set_program_name (argv[0]);
	atexit (olist_free);
	atexit (close_stdout);

        while ((c = getopt_long(argc, argv, "sh", long_options, NULL)) != -1) {
                switch (c){
                        case 's':
                                do_sort = true;
                                break;
			case 'h':
                                usage (EXIT_SUCCESS);
                                break;
                        default:
                                usage (EXIT_FAILURE);
                                break;
                }
        }

	if (optind < argc) {
		int i;
                for (i = optind; i < argc; i++)
                        read_pot_file(argv[i], &olist, false);
        } else {
                read_pot_file("-", &olist, false);
        }
	if (do_sort)
		oid_list_sort(&olist);
	print_oid_list(&olist);
	exit (EXIT_SUCCESS);
}
