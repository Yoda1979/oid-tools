/* Misc OID processing functions
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

int oidcmp(const char *oid1, const char *oid2)
{
	const char *s1, *s2;
	int n1, n2;

	s1 = oid1;
	s2 = oid2;
	while (1) {
		n1 = 0;
		while (*s1 >= '0' && *s1 <= '9') {
			n1 = n1 * 10 + (*s1 - '0');
			s1++;
		}

		n2 = 0;
		while (*s2 >= '0' && *s2 <= '9') {
			n2 = n2 * 10 + (*s2 - '0');
			s2++;
		}

		if (n1 > n2)
			return 1;
		else if (n1 < n2)
			return -1;
		if (*s1 == '\0') {
			if (*s2 == '\0')
				break;
			else if (*s2 == '.')
				return -1;
		} else if (*s2 == '\0') {
			if (*s1 == '.')
				return 1;
		}
		s1++;
		s2++;
	}
	return 0;
}

int oidval(const char *oid)
{
	const char *s;

	if (oid == NULL || *oid == '\0' || *oid == '.')
		return -1;
	s = oid;
	while (*s != '\0') {
		if (!(*s >= '0' && *s <= '9') && *s != '.')
			return -1;
		if (*s == '.') {
			if (*(s + 1) == '\0')	/* Trailing dot */
				return -1;
		}
		s++;
	}
	return 0;
}
