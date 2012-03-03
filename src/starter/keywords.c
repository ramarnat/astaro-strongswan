/* C code produced by gperf version 3.0.2 */
/* Command-line: /usr/bin/gperf -m 10 -C -G -D -t  */
/* Computed positions: -k'1-2,6,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gnu-gperf@gnu.org>."
#endif


/* strongSwan keywords
 * Copyright (C) 2005 Andreas Steffen
 * Hochschule fuer Technik Rapperswil, Switzerland
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <string.h>

#include "keywords.h"

struct kw_entry {
    char *name;
    kw_token_t token;
};

#define TOTAL_KEYWORDS 123
#define MIN_WORD_LENGTH 3
#define MAX_WORD_LENGTH 17
#define MIN_HASH_VALUE 11
#define MAX_HASH_VALUE 241
/* maximum key range = 231, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (str, len)
     register const char *str;
     register unsigned int len;
{
  static const unsigned char asso_values[] =
    {
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242,  29,
       62, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242,  31, 242,  25, 242,  62,
       22,   2,  48,  56,  81,   2, 242, 116,   2,  62,
       31,  54,  23, 242,   4,  10,   3,  39,   3, 242,
        4,  18,   2, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
      242, 242, 242, 242, 242, 242
    };
  register int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[5]];
      /*FALLTHROUGH*/
      case 5:
      case 4:
      case 3:
      case 2:
        hval += asso_values[(unsigned char)str[1]];
      /*FALLTHROUGH*/
      case 1:
        hval += asso_values[(unsigned char)str[0]];
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

static const struct kw_entry wordlist[] =
  {
    {"left",              KW_LEFT},
    {"right",             KW_RIGHT},
    {"lifetime",          KW_KEYLIFE},
    {"leftcert",          KW_LEFTCERT,},
    {"leftfirewall",      KW_LEFTFIREWALL},
    {"leftsendcert",      KW_LEFTSENDCERT},
    {"rightikeport",      KW_RIGHTIKEPORT},
    {"leftprotoport",     KW_LEFTPROTOPORT},
    {"type",              KW_TYPE},
    {"leftgroups",        KW_LEFTGROUPS},
    {"rekey",             KW_REKEY},
    {"rightsubnet",       KW_RIGHTSUBNET},
    {"rightsendcert",     KW_RIGHTSENDCERT},
    {"reqid",             KW_REQID},
    {"leftallowany",      KW_LEFTALLOWANY},
    {"rightid",           KW_RIGHTID},
    {"esp",               KW_ESP},
    {"leftnexthop",       KW_LEFTNEXTHOP},
    {"lifebytes",         KW_LIFEBYTES},
    {"rightrsasigkey",    KW_RIGHTRSASIGKEY},
    {"leftrsasigkey",     KW_LEFTRSASIGKEY},
    {"rightprotoport",    KW_RIGHTPROTOPORT},
    {"virtual_private",   KW_VIRTUAL_PRIVATE},
    {"plutostart",        KW_PLUTOSTART},
    {"strictcrlpolicy",   KW_STRICTCRLPOLICY},
    {"lifepackets",       KW_LIFEPACKETS},
    {"rightsourceip",     KW_RIGHTSOURCEIP},
    {"eap",               KW_EAP},
    {"leftid",            KW_LEFTID},
    {"leftsubnet",        KW_LEFTSUBNET},
    {"ldapbase",          KW_LDAPBASE},
    {"leftca",            KW_LEFTCA},
    {"leftnatip",         KW_LEFTNATIP},
    {"rightallowany",     KW_RIGHTALLOWANY},
    {"inactivity",        KW_INACTIVITY},
    {"rightsubnetwithin", KW_RIGHTSUBNETWITHIN},
    {"rekeyfuzz",         KW_REKEYFUZZ},
    {"installpolicy",     KW_INSTALLPOLICY},
    {"packetdefault",     KW_PACKETDEFAULT},
    {"leftupdown",        KW_LEFTUPDOWN},
    {"rightfirewall",     KW_RIGHTFIREWALL},
    {"rightnatip",        KW_RIGHTNATIP},
    {"rightnexthop",      KW_RIGHTNEXTHOP},
    {"dpddelay",          KW_DPDDELAY},
    {"dumpdir",           KW_DUMPDIR},
    {"nat_traversal",     KW_NAT_TRAVERSAL},
    {"crluri",            KW_CRLURI},
    {"leftcert2",         KW_LEFTCERT2,},
    {"rightid2",          KW_RIGHTID2},
    {"eap_identity",      KW_EAP_IDENTITY},
    {"rightcert",         KW_RIGHTCERT},
    {"certuribase",       KW_CERTURIBASE},
    {"lefthostaccess",    KW_LEFTHOSTACCESS},
    {"rightgroups",       KW_RIGHTGROUPS},
    {"pfs",               KW_PFS},
    {"also",              KW_ALSO},
    {"crlcheckinterval",  KW_CRLCHECKINTERVAL},
    {"rightupdown",       KW_RIGHTUPDOWN},
    {"dpdaction",         KW_DPDACTION},
    {"ldaphost",          KW_LDAPHOST},
    {"leftsubnetwithin",  KW_LEFTSUBNETWITHIN},
    {"uniqueids",         KW_UNIQUEIDS},
    {"xauth_identity",    KW_XAUTH_IDENTITY},
    {"leftsourceip",      KW_LEFTSOURCEIP},
    {"leftid2",           KW_LEFTID2},
    {"mediated_by",       KW_MEDIATED_BY},
    {"me_peerid",         KW_ME_PEERID},
    {"leftca2",           KW_LEFTCA2},
    {"cacert",            KW_CACERT},
    {"rightca",           KW_RIGHTCA},
    {"interfaces",        KW_INTERFACES},
    {"rightauth2",        KW_RIGHTAUTH2},
    {"crluri1",           KW_CRLURI},
    {"plutostderrlog",    KW_PLUTOSTDERRLOG},
    {"authby",            KW_AUTHBY},
    {"mediation",         KW_MEDIATION},
    {"overridemtu",       KW_OVERRIDEMTU},
    {"rekeymargin",       KW_REKEYMARGIN},
    {"righthostaccess",   KW_RIGHTHOSTACCESS},
    {"plutodebug",        KW_PLUTODEBUG},
    {"leftauth2",         KW_LEFTAUTH2},
    {"xauth",             KW_XAUTH},
    {"nocrsend",          KW_NOCRSEND},
    {"dpdtimeout",        KW_DPDTIMEOUT},
    {"rightauth",         KW_RIGHTAUTH},
    {"auto",              KW_AUTO},
    {"ike",               KW_IKE},
    {"forceencaps",       KW_FORCEENCAPS},
    {"mobike",	           KW_MOBIKE},
    {"prepluto",          KW_PREPLUTO},
    {"ocspuri",           KW_OCSPURI},
    {"margintime",        KW_REKEYMARGIN},
    {"leftauth",          KW_LEFTAUTH},
    {"leftikeport",       KW_LEFTIKEPORT},
    {"compress",          KW_COMPRESS},
    {"crluri2",           KW_CRLURI2},
    {"rightca2",          KW_RIGHTCA2},
    {"marginbytes",       KW_MARGINBYTES},
    {"rightcert2",        KW_RIGHTCERT2},
    {"marginpackets",     KW_MARGINPACKETS},
    {"postpluto",         KW_POSTPLUTO},
    {"fragicmp",          KW_FRAGICMP},
    {"auth",              KW_AUTH},
    {"force_keepalive",   KW_FORCE_KEEPALIVE},
    {"hidetos",           KW_HIDETOS},
    {"keep_alive",        KW_KEEP_ALIVE},
    {"pfsgroup",          KW_PFSGROUP},
    {"ocspuri1",          KW_OCSPURI},
    {"cachecrls",         KW_CACHECRLS},
    {"reauth",            KW_REAUTH},
    {"keylife",           KW_KEYLIFE},
    {"ikelifetime",       KW_IKELIFETIME},
    {"pkcs11module",      KW_PKCS11MODULE},
    {"pkcs11keepstate",   KW_PKCS11KEEPSTATE},
    {"charonstart",       KW_CHARONSTART},
    {"ocspuri2",          KW_OCSPURI2},
    {"pkcs11initargs",    KW_PKCS11INITARGS},
    {"keyexchange",       KW_KEYEXCHANGE},
    {"keyingtries",       KW_KEYINGTRIES},
    {"pkcs11proxy",       KW_PKCS11PROXY},
    {"klipsdebug",        KW_KLIPSDEBUG},
    {"modeconfig",        KW_MODECONFIG},
    {"charondebug",       KW_CHARONDEBUG}
  };

static const short lookup[] =
  {
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,   0,  -1,  -1,   1,  -1,   2,   3,  -1,  -1,
      4,   5,  -1,   6,   7,  -1,  -1,   8,   9,  10,
     11,  -1,  12,  13,  -1,  -1,  14,  15,  16,  -1,
     17,  18,  19,  -1,  -1,  20,  21,  22,  23,  24,
     25,  -1,  26,  27,  28,  -1,  29,  -1,  -1,  30,
     31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
     41,  -1,  42,  43,  44,  45,  46,  47,  48,  49,
     50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
     60,  61,  62,  63,  -1,  64,  65,  66,  67,  68,
     69,  70,  -1,  71,  72,  73,  74,  75,  -1,  76,
     77,  -1,  78,  79,  80,  81,  -1,  82,  -1,  -1,
     83,  84,  85,  86,  -1,  87,  88,  -1,  89,  90,
     91,  -1,  92,  -1,  93,  -1,  94,  95,  96,  97,
     98,  99, 100,  -1,  -1, 101,  -1,  -1,  -1, 102,
    103,  -1,  -1,  -1, 104, 105, 106, 107,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1, 108,  -1,
     -1,  -1,  -1,  -1, 109, 110,  -1,  -1,  -1, 111,
     -1,  -1, 112,  -1,  -1, 113,  -1,  -1, 114,  -1,
    115,  -1, 116, 117,  -1, 118,  -1, 119,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1, 120,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1, 121,  -1,  -1,  -1,
     -1, 122
  };

#ifdef __GNUC__
__inline
#endif
const struct kw_entry *
in_word_set (str, len)
     register const char *str;
     register unsigned int len;
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register int index = lookup[key];

          if (index >= 0)
            {
              register const char *s = wordlist[index].name;

              if (*str == *s && !strcmp (str + 1, s + 1))
                return &wordlist[index];
            }
        }
    }
  return 0;
}
