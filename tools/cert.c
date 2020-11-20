/* Utility for creation test x509 certificate
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
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define FORMAT_ASN1     1
#define FORMAT_PEM      2

#define SERIALNUMBER_SIZE	4

ASN1_INTEGER *fcal_generate_serial()
{
	ASN1_INTEGER *serial;
	unsigned char *data;
	time_t tm;
	int i;

	if ((data = OPENSSL_malloc(SERIALNUMBER_SIZE + 1)) == NULL)
                return NULL;
        bzero (data, SERIALNUMBER_SIZE + 1);

	if (time(&tm) == ((time_t) -1))
		goto err;
	for (i = 0; i < sizeof(uint32_t); i++) {
                data[i] = tm & 0xff;
                tm >>= 8;
        }
	if ((serial = ASN1_INTEGER_new()) == NULL) {
                OPENSSL_free (data);
                return NULL;
        }
        serial->type = V_ASN1_INTEGER;
        serial->data = data;
        serial->length = SERIALNUMBER_SIZE;
        return serial;
err:
	OPENSSL_free (data);
	return NULL;
}

X509_NAME *fcal_generate_issuer()
{
	X509_NAME *name;
	ASN1_OBJECT *obj;
	ASN1_STRING *value;
	ASN1_STRING_TABLE *tbl;
	char *s;
	int r;

	if ((name = X509_NAME_new ()) == NULL)
		return NULL;

	// common name
	obj = OBJ_nid2obj (NID_commonName);
	if (obj == NULL)
		goto err;
	value = NULL;
	s = "Удостоверяющий центр 1 (Certification Authority 1)";
	if ((tbl = ASN1_STRING_TABLE_get(NID_commonName)) == NULL)
		goto err;
	r = ASN1_mbstring_ncopy (&value, (const unsigned char *)s, strlen(s), MBSTRING_UTF8, B_ASN1_UTF8STRING, tbl->minsize, tbl->maxsize);
	if (r <= 0) {
                printf ("Failed to copy mbstring: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	if (value == NULL)
		goto err;
	r = X509_NAME_add_entry_by_OBJ (name, obj, value->type, value->data, value->length, -1, 0);
	if (!r)
		goto err;

	// organization
	obj = OBJ_nid2obj (NID_organizationName);
	if (obj == NULL)
		goto err;
	value = NULL;
	s = "ООО \"Вектор\"";
	if ((tbl = ASN1_STRING_TABLE_get(NID_organizationName)) == NULL)
		goto err;
	r = ASN1_mbstring_ncopy (&value, (const unsigned char *)s, strlen(s), MBSTRING_UTF8, B_ASN1_UTF8STRING, tbl->minsize, tbl->maxsize);
	if (r <= 0) {
                printf ("Failed to copy mbstring: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	if (value == NULL)
		goto err;
	r = X509_NAME_add_entry_by_OBJ (name, obj, value->type, value->data, value->length, -1, 0);
	if (!r)
		goto err;

	// country
	obj = OBJ_nid2obj (NID_countryName);
	if (obj == NULL)
		goto err;
	value = NULL;
	s = "RU";
	if ((tbl = ASN1_STRING_TABLE_get(NID_countryName)) == NULL)
		goto err;
	r = ASN1_mbstring_ncopy (&value, (const unsigned char *)s, strlen(s), MBSTRING_UTF8, B_ASN1_UTF8STRING, tbl->minsize, tbl->maxsize);
	if (r <= 0) {
                printf ("Failed to copy mbstring: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	if (value == NULL)
		goto err;
	r = X509_NAME_add_entry_by_OBJ (name, obj, value->type, value->data, value->length, -1, 0);
	if (!r)
		goto err;

	// locality
	obj = OBJ_nid2obj (NID_localityName);
	if (obj == NULL)
		goto err;
	value = NULL;
	s = "Москва";
	if ((tbl = ASN1_STRING_TABLE_get(NID_localityName)) == NULL)
		goto err;
	r = ASN1_mbstring_ncopy (&value, (const unsigned char *)s, strlen(s), MBSTRING_UTF8, B_ASN1_UTF8STRING, tbl->minsize, tbl->maxsize);
	if (r <= 0) {
                printf ("Failed to copy mbstring: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	if (value == NULL)
		goto err;
	r = X509_NAME_add_entry_by_OBJ (name, obj, value->type, value->data, value->length, -1, 0);
	if (!r)
		goto err;

	// ogrn
	obj = OBJ_txt2obj ("1.2.643.100.1", 1);
	if (obj == NULL)
		goto err;
	value = NULL;
	s = "0123456789012";
	r = ASN1_mbstring_ncopy (&value, (const unsigned char *)s, strlen(s), MBSTRING_UTF8, B_ASN1_NUMERICSTRING, 13, 13);
	if (r <= 0) {
                printf ("Failed to copy mbstring: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	if (value == NULL)
		goto err;
	r = X509_NAME_add_entry_by_OBJ (name, obj, value->type, value->data, value->length, -1, 0);
	if (!r)
		goto err;
	return name;
err:
	X509_NAME_free (name);
	return NULL;
}

X509_NAME *fcal_generate_subject()
{
	X509_NAME *name;
	ASN1_OBJECT *obj;
	ASN1_STRING *value;
	ASN1_STRING_TABLE *tbl;
	char *s;
	int r;

	if ((name = X509_NAME_new ()) == NULL)
		return NULL;

	// common name
	obj = OBJ_nid2obj (NID_commonName);
	if (obj == NULL)
		goto err;
	value = NULL;
	s = "Иванов Пётр Сергеевич";
	if ((tbl = ASN1_STRING_TABLE_get(NID_commonName)) == NULL)
		goto err;
	r = ASN1_mbstring_ncopy (&value, (const unsigned char *)s, strlen(s), MBSTRING_UTF8, B_ASN1_BMPSTRING, tbl->minsize, tbl->maxsize);
	if (r <= 0)
		goto err;
	if (value == NULL)
		goto err;
	r = X509_NAME_add_entry_by_OBJ (name, obj, value->type, value->data, value->length, -1, 0);
	if (!r)
		goto err;

	// organization
	obj = OBJ_nid2obj (NID_organizationName);
	if (obj == NULL)
		goto err;
	value = NULL;
	s = "Физфак МГУ";
	if ((tbl = ASN1_STRING_TABLE_get(NID_organizationName)) == NULL)
		goto err;
	r = ASN1_mbstring_ncopy (&value, (const unsigned char *)s, strlen(s), MBSTRING_UTF8, B_ASN1_UTF8STRING, tbl->minsize, tbl->maxsize);
	if (r <= 0) {
                printf ("Failed to copy mbstring: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	if (value == NULL)
		goto err;
	r = X509_NAME_add_entry_by_OBJ (name, obj, value->type, value->data, value->length, -1, 0);
	if (!r)
		goto err;

	// country
	obj = OBJ_nid2obj (NID_countryName);
	if (obj == NULL)
		goto err;
	value = NULL;
	s = "RU";
	if ((tbl = ASN1_STRING_TABLE_get(NID_countryName)) == NULL)
		goto err;
	r = ASN1_mbstring_ncopy (&value, (const unsigned char *)s, strlen(s), MBSTRING_UTF8, B_ASN1_UTF8STRING, tbl->minsize, tbl->maxsize);
	if (r <= 0) {
                printf ("Failed to copy mbstring: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	if (value == NULL)
		goto err;
	r = X509_NAME_add_entry_by_OBJ (name, obj, value->type, value->data, value->length, -1, 0);
	if (!r)
		goto err;

	// locality
	obj = OBJ_nid2obj (NID_localityName);
	if (obj == NULL)
		goto err;
	value = NULL;
	s = "Керчь";
	if ((tbl = ASN1_STRING_TABLE_get(NID_localityName)) == NULL)
		goto err;
	r = ASN1_mbstring_ncopy (&value, (const unsigned char *)s, strlen(s), MBSTRING_UTF8, B_ASN1_UTF8STRING, tbl->minsize, tbl->maxsize);
	if (r <= 0) {
                printf ("Failed to copy mbstring: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	if (value == NULL)
		goto err;
	r = X509_NAME_add_entry_by_OBJ (name, obj, value->type, value->data, value->length, -1, 0);
	if (!r)
		goto err;

	// inn
	obj = OBJ_txt2obj ("1.2.643.3.131.1.1", 1);
	if (obj == NULL)
		goto err;
	value = NULL;
	s = "987654321098";
	r = ASN1_mbstring_ncopy (&value, (const unsigned char *)s, strlen(s), MBSTRING_UTF8, B_ASN1_NUMERICSTRING, 12, 12);
	if (r <= 0) {
                printf ("Failed to copy mbstring: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	if (value == NULL)
		goto err;
	r = X509_NAME_add_entry_by_OBJ (name, obj, value->type, value->data, value->length, -1, 0);
	return name;
err:
	X509_NAME_free (name);
	return NULL;
}

EVP_PKEY* EVP_PKEY_gost_keygen(ENGINE* e, int type, int param_nid)
{
        EVP_PKEY *pk = NULL;
        EVP_PKEY_CTX *ctx = NULL;
        const char* name;

        if (!e)
                return NULL;
        if ((ctx = EVP_PKEY_CTX_new_id(type, e)) == NULL)
                return NULL;
        if (EVP_PKEY_keygen_init(ctx) <= 0)
                goto out;
        name = OBJ_nid2sn(param_nid);
        if (name == NULL)
                goto out;
        if (EVP_PKEY_CTX_ctrl_str(ctx, "paramset", name) <= 0)
                goto out;
        EVP_PKEY_keygen(ctx, &pk);
out:
        if (ctx)
                EVP_PKEY_CTX_free(ctx);
        return pk;
}

ASN1_OCTET_STRING *fca_pack_extension_octet(int nid, ASN1_VALUE *val)
{
        ASN1_OBJECT *obj;
        const X509V3_EXT_METHOD *method;
        ASN1_OCTET_STRING *ext_oct;
        unsigned char *ext_der;
        int ext_len;

        if ((obj = OBJ_nid2obj(nid)) == NULL)
                return NULL;
        if ((method = X509V3_EXT_get_nid(nid)) == NULL)
                return NULL;
        if ((ext_oct = ASN1_OCTET_STRING_new()) == NULL)
                return NULL;
        if (method->it) {
                ext_der = NULL;
                ext_len = ASN1_item_i2d(val, &ext_der, ASN1_ITEM_ptr(method->it));
                if (ext_len < 0)
                        goto err;
        } else {
                unsigned char *s;
                ext_len = method->i2d(val, NULL);
                if((ext_der = malloc(ext_len)) == NULL)
                        goto err;
                s = ext_der;
                method->i2d(val, &s);
        }
        ext_oct->data = ext_der;
        ext_oct->length = ext_len;
        return ext_oct;
err:
        ASN1_OCTET_STRING_free (ext_oct);
        return NULL;
}

X509_EXTENSION *create_eku(const char *name)
{
	X509_EXTENSION *ex;
	EXTENDED_KEY_USAGE *eku;
	ASN1_OBJECT *obj;
        ASN1_OCTET_STRING *ext_oct;
	FILE *file;
	char *line = NULL;
        size_t n;
        ssize_t read;

	if ((eku = sk_ASN1_OBJECT_new_null()) == NULL)
		return NULL;
	if ((file = fopen(name, "r")) == NULL)
		goto err;
	while ((read = getline(&line, &n, file)) != -1) {
		if (line[0] == '\n' || line[0] == '#')
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
		if ((obj = OBJ_txt2obj(line, 1)) == NULL) {
			fprintf(stderr, "OBJ_txt2obj failed %s\n", ERR_error_string(ERR_get_error(), NULL));
			fprintf(stderr, "OID %s\n", line);
			goto err_file;
		}
		sk_ASN1_OBJECT_push(eku, obj);
	}
	if (line)
                free (line);
        fclose(file);
	if ((ext_oct = fca_pack_extension_octet(NID_ext_key_usage, (ASN1_VALUE *)eku)) == NULL)
		goto err;
	if ((ex = X509_EXTENSION_create_by_NID(NULL, NID_ext_key_usage, 0, ext_oct)) == NULL) {
		ASN1_OCTET_STRING_free (ext_oct);
		goto err;
	}
	ASN1_OCTET_STRING_free (ext_oct);
	sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
	return ex;
err_file:
	fclose(file);
err:
	sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
	return 0;
}

X509 *create_cert(ENGINE *e, const char *file)
{
	X509 *x;
	X509_NAME *name;
	X509_EXTENSION *ex;
	ASN1_INTEGER *serial;
	ASN1_TIME *tm;
	EVP_PKEY *pbkey, *pk;
	time_t t0, t1;
	const EVP_MD *md;

	if ((x = X509_new()) == NULL)
		return NULL;
	if (!X509_set_version(x, 2))
                goto err;
	serial = fcal_generate_serial();
	if (serial == NULL)
		goto err;
	if (!X509_set_serialNumber(x, serial)) {
                ASN1_INTEGER_free (serial);
                goto err;
        }
        ASN1_INTEGER_free (serial);

	// issuer & subject
	name = fcal_generate_issuer();
	if (name == NULL)
		goto err;
	if (!X509_set_issuer_name(x, name)) {
		X509_NAME_free (name);
		goto err;
	}
	X509_NAME_free (name);

	name = fcal_generate_subject();
	if (name == NULL)
		goto err;
	if (!X509_set_subject_name(x, name)) {
		X509_NAME_free (name);
		goto err;
	}
	X509_NAME_free (name);

	// time
	if (time(&t0) == -1)
		goto err;
	if ((tm = ASN1_TIME_set(NULL, t0)) == NULL)
		goto err;
	if (!X509_set_notBefore(x, tm)) {
                ASN1_TIME_free (tm);
                goto err;
        }
        ASN1_TIME_free (tm);

	t1 = t0 + 31536000;
	if ((tm = ASN1_TIME_set(NULL, t1)) == NULL)
                goto err;
        if (!X509_set_notAfter(x, tm)) {
                ASN1_TIME_free (tm);
                goto err;
        }
        ASN1_TIME_free (tm);

	// pubkey
        if ((pbkey = EVP_PKEY_gost_keygen(e, NID_id_GostR3410_2001, NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet)) == NULL) {
		fprintf(stderr, "EVP_PKEY_gost_keygen failed %s\n", ERR_error_string(ERR_get_error(), NULL));
                goto err;
	}
        if (!X509_set_pubkey(x, pbkey)) {
                EVP_PKEY_free (pbkey);
                goto err;
        }
        EVP_PKEY_free (pbkey);

	// extensions
	if (1) {
		X509V3_CTX ctx;
        	X509V3_set_ctx_nodb(&ctx);
	        X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
		ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "digitalSignature");
                if (ex == NULL)
                        goto err;
                if (!X509_add_ext(x, ex, -1)) {
                        X509_EXTENSION_free (ex);
                        goto err;
                }
                X509_EXTENSION_free (ex);
	}

	if (1) {
		ex = create_eku(file);
                if (ex == NULL)
                        goto err;
                if (!X509_add_ext(x, ex, -1)) {
                        X509_EXTENSION_free (ex);
                        goto err;
                }
                X509_EXTENSION_free (ex);
	}
	
	if (1) {
                X509V3_CTX ctx;
                X509V3_set_ctx_nodb (&ctx);
                X509V3_set_ctx(&ctx, NULL, x, NULL, NULL, 0);
                ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
                if (ex == NULL)
                        goto err;
                if (!X509_add_ext(x, ex, -1)) {
                        X509_EXTENSION_free (ex);
                        goto err;
                }
                X509_EXTENSION_free (ex);
        }

	if ((md = EVP_get_digestbyname("md_gost12_512")) == NULL) {
		fprintf(stderr, "EVP_get_digestbyname failed %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	if ((pk = EVP_PKEY_gost_keygen(e, NID_id_GostR3410_2012_512, NID_id_tc26_gost_3410_2012_512_paramSetA)) == NULL)
		goto err;
	if (!X509_sign(x, pk, md)) {
		EVP_PKEY_free (pk);
		goto err;
	}
	EVP_PKEY_free (pk);
	return x;
err:
	X509_free (x);
        return NULL;
}

int fcal_write_certificate(char *name, X509 *x, int type)
{
        BIO *bio;
        FILE *file;
        int r;

        if ((file = fopen(name, "w")) == NULL)
                return -1;

        if ((bio=BIO_new_fp(file, BIO_NOCLOSE)) == NULL) {
                fclose(file);
                return -1;
        }

        if (type == FORMAT_ASN1) {
                r = i2d_X509_bio(bio, x);
        } else {
                r = PEM_write_bio_X509(bio, x);
        }

        BIO_free(bio);
        fclose(file);
        return (r == 0 ? -1 : 0);
}

int main(int argc, char *argv[])
{
	X509 *x;
	int ret = EXIT_FAILURE;
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
            "dynamic_path = /usr/lib64/engines-1.1/gost.so\n"
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
                return EXIT_FAILURE;
        }

	x = create_cert(e, argv[1]);
	if (x == NULL) {
		printf ("Failed to create certificate\n");
                return EXIT_FAILURE;
	}

	if (fcal_write_certificate("test.cer", x, FORMAT_PEM) != 0) {
		printf ("Failed to write certificate\n");
		goto out;
	}
	ret = EXIT_SUCCESS;
out:
	X509_free (x);
	return ret;
}
