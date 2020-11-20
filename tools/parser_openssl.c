/* Utility for parsing obj_mac.h from openssl, short names (SN_) are ignored
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
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

#define BUF_SIZE                4096

char nid_str[BUF_SIZE];
char ln_str[BUF_SIZE];
char sn_str[BUF_SIZE];
char obj_str[BUF_SIZE];

void proc_entry(void)
{
	ASN1_OBJECT *obj;
	char oid[BUF_SIZE], *s;
	int nid;

	if (nid_str[0] == 0)
		return;
	s = strrchr(nid_str, ' ');
	if (s == NULL) {
		fprintf (stderr, "Bad NID string %s\n", nid_str);
                exit (EXIT_FAILURE);
	}

	s++;
	if (strlen(s) == 0) {
		fprintf (stderr, "Bad NID string %s\n", nid_str);
                exit (EXIT_FAILURE);
	}

	nid = atoi(s);

	obj = OBJ_nid2obj(nid);
	if (obj == NULL) {
		fprintf (stderr, "Bad NID string %s, failed to create object\n", nid_str);
		exit (EXIT_FAILURE);
	}

	if (OBJ_obj2txt(oid, BUF_SIZE, obj, 1) <= 0) {
//		fprintf (stderr, "Bad object %s, failed to get oid\n", nid_str);
		return;
	}

	if (strlen(ln_str) != 0) {
		s = strrchr(ln_str, '"');
		if (s == NULL) {
			fprintf (stderr, "Bad long name string %s\n", ln_str);
			exit (EXIT_FAILURE);
		}
		*s = '\0';

		s = strrchr(ln_str, '"');
		if (s == NULL) {
			fprintf (stderr, "Bad long name string %s\n", ln_str);
			exit (EXIT_FAILURE);
		}
		*s = '\0';
		s++;

//		if (strcmp(s, OBJ_nid2ln(nid))) {
//			fprintf (stderr, "Bad long name %s\t%s\n", s, OBJ_nid2ln(nid));
//			exit (EXIT_FAILURE);
//		}

        	fprintf (stdout, "msgid \"%s\"\n", oid);
        	fprintf (stdout, "msgstr \"%s\"\n", s);
        	fprintf (stdout, "\n");
	}
	return;
}

int main(int argc, char *argv[])
{
	FILE *file;
	char *s, *line = NULL, *k;
	size_t n;
	ssize_t read;
	ENGINE *e;
	CONF *pConfig = NCONF_new(NULL);
        BIO *bpConf;
        long lErrLine;
        char sConf[] =
            "openssl_conf = openssl_def\n"
            "\n"
            "[openssl_def]\n"
            "engines = engine_section\n"
            "\n"
            "[engine_section]\n"
            "gost = gost_section\n"
            "\n"
            "[gost_section]\n"
            "engine_id = gost\n"
            "dynamic_path = ../../openssl_gost/gost.so\n"
            "default_algorithms = ALL\n"
            "CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet\n"
            "\n"
            ;

	ERR_load_crypto_strings();
        ENGINE_load_builtin_engines();
        OPENSSL_load_builtin_modules();

	bpConf = BIO_new_mem_buf(sConf, -1);
        if(!NCONF_load_bio(pConfig, bpConf, &lErrLine)) {
                fflush(NULL);
                fprintf(stderr, "NCONF_load_bio: ErrLine=%ld: %s\n", lErrLine, ERR_error_string(ERR_get_error(), NULL));
                return EXIT_FAILURE;
        }
        BIO_free(bpConf);

        if(!CONF_modules_load(pConfig, NULL, 0)) {
                fflush(NULL);
                fprintf(stderr, "CONF_modules_load: %s\n", ERR_error_string(ERR_get_error(), NULL));
                return EXIT_FAILURE;
        }

	if((e = ENGINE_by_id("gost")) == NULL) {
                printf ("Failed to get engine: %s\n", ERR_error_string(ERR_get_error(), NULL));
                exit (EXIT_FAILURE);
        }

	if ((file = fopen(argv[1], "r")) == NULL) {
		fprintf (stderr, "Failed to open %s file\n", argv[1]);
		exit (EXIT_FAILURE);
	}

	while ((read = getline(&line, &n, file)) != -1) {
		if (line[read - 1] == '\n') {
			line[read - 1] = '\0';
		} else {
			char *buf;
			buf = malloc(read + 1);
			if (buf == NULL) {
				fprintf (stderr, "Malloc error\n");
				exit (EXIT_FAILURE);
				continue;
			}
			memcpy (buf, line, read);
			buf[read] = '\0';
			free (line);
			line = buf;
			n++;
		}
		k = line;

		if (*k == '\n' || *k == ' ' || *k == '\0') {
			proc_entry();
			*nid_str = '\0';
			*ln_str = '\0';
			*sn_str = '\0';
			*obj_str = '\0';
	       		continue;
		}

		s = "#define NID_";
		if (!strncmp(s, k, strlen(s))) {
			snprintf (nid_str, BUF_SIZE, "%s", k + 8);
			continue;
		}
		s = "#define SN_";
		if (!strncmp(s, k, strlen(s))) {
			snprintf (sn_str, BUF_SIZE, "%s", k + 8);
			continue;
		}
		s = "#define LN_";
		if (!strncmp(s, k, strlen(s))) {
			snprintf (ln_str, BUF_SIZE, "%s", k + 8);
			continue;
		}
		s = "#define OBJ_";
		if (!strncmp(s, k, strlen(s))) {
			snprintf (obj_str, BUF_SIZE, "%s", k+ 8);
			continue;
		}

	}
	proc_entry();
	if (line)
		free (line);

	fclose (file);
	return EXIT_SUCCESS;
}
