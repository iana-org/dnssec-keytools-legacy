/*
 * $Id: rlder.c 567 2010-10-28 05:11:10Z jakob $
 *
 * Copyright (C) 2006 Richard H. Lamb ("RHL") slamb@xtcn.com
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
 
#include <ctype.h>

#include "util.h"
#include "logger.h"
#include "rlder.h"

#define NARGS 50
#define OID_MAX_LEN 256

static int setlen(mbuf *bp,int n);

/*! OID encoding support - some shortcuts for well known */
struct oidtable {
  char *str;
  int len;
  uint8_t *data;
};

static struct oidtable oids[] = {
  { "countryName",3,(uint8_t *)"\x55\x04\x06" },
  { "stateOrProvinceName",3,(uint8_t *)"\x55\x04\x08" },
  { "localityName",3,(uint8_t *)"\x55\x04\x07" },
  { "organizationName",3,(uint8_t *)"\x55\x04\x0a" },
  { "organizationalUnitName",3,(uint8_t *)"\x55\x04\x0b" },
  { "commonName",3,(uint8_t *)"\x55\x04\x03" },
  { "emailAddress",9,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01" },
  { "x509v3BasicConstraints",3,(uint8_t *)"\x55\x1d\x13" },
  { "x509v3KeyUsage",3,(uint8_t *)"\x55\x1d\x0f" },
  { "x509v3ExtendedKeyUsage",3,(uint8_t *)"\x55\x1d\x25" },
  { "x509v3CRLDistributionPoints",3,(uint8_t *)"\x55\x1d\x1f" },
  { "x509v3CertificatePolicies",3,(uint8_t *)"\x55\x1d\x20" },
  { "x509v3AuthorityKeyIdentifier",3,(uint8_t *)"\x55\x1d\x23" },
  { "x509v3SubjectAlternativeName",3,(uint8_t *)"\x55\x1d\x11" },
  { "x509v3SubjectKeyIdentifier",3,(uint8_t *)"\x55\x1d\x0e" },
  { "authorityInformationAccess",8,(uint8_t *)"\x2b\x06\x01\x05\x05\x07\x01\x01" },
  { "sha1",5,(uint8_t *)"\x2b\x0e\x03\x02\x1a" },
  { "sha256",9,(uint8_t *)"\x60\x86\x48\x01\x65\x03\x04\x02\x01" },
  { "1.2.840.113549.1.9.16.1.27",11,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x1B" },
  { "pkcs7-signedData",9,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" },
  { "pkcs7-data",9,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01" },
  { "rsaEncryption",9,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" },
  { "sha1WithRSAEncryption",9,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05" },
  /*! 1 2 840 113549 1 1 5 */
  { "sha256WithRSAEncryption",9,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b" },
  /*! 1 2 840 113549 1 1 11 */
  { "timeStampToken",11,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x0e" },
  { "contentType",9,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x03" },
  { "ct-TSTInfo",11,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x04" },
  { "signingTime",9,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x05" },
  { "messageDigest",9,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04" },
  { "aa-securityLabel",11,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x02" },
  { "aa-signingCertificate",11,(uint8_t *)"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x0c" },
  { "1.3.6.1.4.1.5309.1.2.2",10,(uint8_t *)"\x2b\x06\x01\x04\x01\xa9\x3d\x01\x02\x02" },
  { "1.3.6.1.4.1.5309.1.2.3",10,(uint8_t *)"\x2b\x06\x01\x04\x01\xa9\x3d\x01\x02\x03" },
  { "1.1.2",2,(uint8_t *)"\x29\x02" },
  { "emailProtection",8,(uint8_t *)"\x2b\x06\x01\x05\x05\x07\x03\x04" },
  /*!  resourceRecord = iso(1) identified-organization(3) dod(6) internet(1)
                       private(4) enterprise(1) iana(1000) iana-dns(53) */
  { "1.3.6.1.4.1.1000.53",8,(uint8_t *)"\x2b\x06\x01\x04\x01\x87\x68\x35" },
  { NULL, 0, NULL }
};
/* ... and then general purpose OID encoding */
/*011639086226200*/

/*! local variable for walking a DER struct and printing contents */
static int depth = 0;

/*******************************************************************
 *  DER Primitives: mbuf *func(derb *db, value)
 *  input: db keeps track of end of mbuf chain, value (depends on function)
 *  output: a new mbuf containing the der encoded value appended to mbuf 
 *          chain (tail pointed in db)
 *******************************************************************/

/*! append an integer - max size (n) <0x10000 to mbuf chain in db 
    \param db work structure accumulating DER elements
    \param n < 65536 integer to encode into DER format
    \return pointer to new mbuf or NULL if error
 */
mbuf *rlder_integer(derb *db,int n)
{
  mbuf *bp;

  if(n < 0x100) {
    if((bp=alloc_mbuf(3)) == NULL) return NULL;
    *bp->pc++ = 0x02; /* integer */
    *bp->pc++ = 0x01;
    *bp->pc++ = (uint8_t)n;
    if(db->bpN) db->bpN->next = bp;
    db->bpN = bp;
    return bp;
  } else if(n < 0x10000) {
    if((bp=alloc_mbuf(4)) == NULL) return NULL;
    *bp->pc++ = 0x02; /* integer */
    *bp->pc++ = 0x02;
    *bp->pc++ = (uint8_t)(n>>8);
    *bp->pc++ = (uint8_t)(n&0xFF);
    if(db->bpN) db->bpN->next = bp;
    db->bpN = bp;
    return bp;
  }
  myx_syslog(LOG_ERR,"error: in %s\n",__func__);
  return NULL;
}

/*! append big int in (q,n) to mbuf chain in db. prepends a 0x00 for safety 
    \param db work structure accumulating DER elements
    \param q pointer to buffer containing integer
    \param n length of above buffer
    \return pointer to new mbuf or NULL if error
*/
mbuf *rlder_binteger(derb *db,uint8_t *q,int n)
{
  mbuf *bp;

  if(q == NULL || n < 0) return NULL;
  /* id(1)+len(3)+pad(1)+n */
  if((bp=alloc_mbuf(5 + n)) == NULL) return NULL;
  *bp->pc++ = 0x02;

  if((*q)&0xFE) {
    setlen(bp,n+1);
    *bp->pc++ = 0x00;
  } else {
    setlen(bp,n);
  }

  memcpy(bp->pc,q,n);
  bp->pc += n;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! Helper routine for OID DER encoding below. fst must = 1 on First call

    \param i value in dotted OID lsit
    \param fst 1 of first call.
    \param len ptr to storage for accumulated length
    \param out accumulating output buffer
 */
static void b7fout(uint32_t i,int fst,int *len,uint8_t *out)
{
  if(i > 0x7F) b7fout(i >> 7,0,len,out);
  i &= 0x7F;
  if(!fst) i |= 0x80;
  if(*len < OID_MAX_LEN) {
    out[*len] = (uint8_t)i;
    *len = *len + 1;
  } else {
    myx_syslog(LOG_ERR,"error: %s %d too long for buffer.\n",__func__,*len);
  }
}

/*! prepare OID

    See 8.19.4 of X.690 OID encoding for details
    http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
    \param str dotted OID string
    \param out binary OID representation of input string
    \return -1 if error; otherwise number of bytes in out
 */
static int oidprep(const char *str,uint8_t *out)
{
  char *p,*q,*r;
  int i,j,len;

  i = 0;
  for(p=(char *)str;*p;p++) {
    if(*p == '.' && i) i = 0;
    else if(isdigit(*p)) i++;
    else {
      myx_syslog(LOG_ERR,"error: %s Non-numeric malformed OID \"%s\"\n",__func__,str);
      return -1;
    }
  }
  if((r=strdup(str)) == NULL) {
    myx_syslog(LOG_ERR,"error: %s Can not allocate string space.\n",__func__);
    return -1;
  }
  p = r;
  len = 0;
  j = 0;
  while(*p) {
    q = strchr(p,'.');
    if(q) *q = '\0';
    if(j == 0) {
      i = 40*atoi(p);
    } else {
      i += atoi(p);
      b7fout(i,1,&len,out);
      i = 0;
    }
    p += strlen(p);
    if(q) p++;
    j++;
  }
  free(r);
  return len;
}

/*! append oid to current mbuf chain in db 

    \param db work struct for accumulating DER elements
    \param idstr OID name or dotted numberic str
    \return NULL if error; new filled in mbuf with DER OID otherwise
 */
mbuf *rlder_objid(derb *db,const char *idstr)
{
  mbuf *bp;
  struct oidtable *ids;

  if(idstr == NULL) return NULL;
  for(ids=oids;ids->str;ids++) {
    if(strcmp(ids->str,idstr)) continue;
    /* id(1)+len(3)+n */
    if((bp=alloc_mbuf(4 + ids->len)) == NULL) return NULL;
    *bp->pc++ = 0x06; /* object id */
    setlen(bp,ids->len);
    memcpy(bp->pc,ids->data,ids->len);
    bp->pc += ids->len;
    if(db->bpN) db->bpN->next = bp;
    db->bpN = bp;
    return bp;
  }
  if(idstr[0] >= '0' && idstr[0] <= '9' && strchr(idstr,'.')) {
    int n;
    uint8_t out[OID_MAX_LEN];
    if((n = oidprep(idstr,out)) < 0) return NULL;
    /* id(1)+len(3)+n */
    if((bp=alloc_mbuf(4 + n)) == NULL) return NULL;
    *bp->pc++ = 0x06; /* object id */
    setlen(bp,n);
    memcpy(bp->pc,out,n);
    bp->pc += n;
    if(db->bpN) db->bpN->next = bp;
    db->bpN = bp;
    return bp;
  }
  myx_syslog(LOG_ERR,"error: %s \"%s\"\n",__func__,idstr);
  return NULL;
}

/*! append bitstring (q,n) to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param q ptr to bytes for bitstring
    \param n number of bytes (full bytes only)
    \return NULL if error; new mbuf filled with DER bitstring otherwise
 */
mbuf *rlder_bitstring(derb *db,uint8_t *q,int n)
{
  mbuf *bp;

  if(q == NULL || n < 0) return NULL;
  /* id(1)+len(3)+bitpad(1)+n */
  if((bp=alloc_mbuf(5 + n)) == NULL) return NULL;
  *bp->pc++ = 0x03; /* bitstring */
  /* always assume n = number of bytes so zero unused bits */
  setlen(bp,n+1);
  *bp->pc++ = 0x00;
  memcpy(bp->pc,q,n);
  bp->pc += n;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append octet (q,n) to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param q ptr to bytes for octet string
    \param n number of bytes (full bytes only)
    \return NULL if error; new mbuf filled in with DER octet otherwise
*/
mbuf *rlder_octet(derb *db,uint8_t *q,int n)
{
  mbuf *bp;

  if(q == NULL || n < 0) return NULL;
  /* id(1)+len(3)+n */
  if((bp=alloc_mbuf(4 + n)) == NULL) return NULL;
  *bp->pc++ = 0x04; /* octet */
  setlen(bp,n);
  memcpy(bp->pc,q,n);
  bp->pc += n;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append ASCIIZ printable string str to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param str ptr to ASCIIZ string
    \return NULL if error; new mbuf filled in with DER printable string otherwise
*/
mbuf *rlder_pstring(derb *db,char *str)
{
  mbuf *bp;
  int n;

  if(str == NULL) return NULL;
  n = strlen(str);
  /* id(1)+len(3)+n+null(1) */
  if((bp=alloc_mbuf(4 + n + 1)) == NULL) return NULL;
  *bp->pc++ = 0x13; /* printablestring */
  setlen(bp,n);
  memcpy(bp->pc,str,n);
  bp->pc += n;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append NULL to mbuf chain in db

    \param db work struct to accumulate DER elements
    \return NULL if error; new mbuf filled in with DER NULL otherwise
*/
mbuf *rlder_nullval(derb *db)
{
  mbuf *bp;

  if((bp=alloc_mbuf(2)) == NULL) return NULL;
  *bp->pc++ = 0x05; /* null */
  *bp->pc++ = 0x00;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append EOC to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \return NULL if error; new mbuf filled in with DER end of content otherwise
*/
mbuf *rlder_eoc(derb *db)
{
  mbuf *bp;

  if((bp=alloc_mbuf(2)) == NULL) return NULL;
  *bp->pc++ = 0x00; /* eoc */
  *bp->pc++ = 0x00;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append boolean tf to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param tf true or false
    \return NULL if error; new mbuf filled in with DER boolean otherwise
*/
mbuf *rlder_booleanv(derb *db,int tf)
{
  mbuf *bp;

  if((bp=alloc_mbuf(3)) == NULL) return NULL;
  *bp->pc++ = 0x01; /* boolean */
  *bp->pc++ = 0x01;
  if(tf) *bp->pc++ = 0xff;
  else *bp->pc++ = 0x00;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append utf8 str (q,n) to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param q pointer to buffer with UTF8 string
    \param n length of above in bytes
    \return NULL if error; new mbuf filled in with DER UTF8 string otherwise
*/
mbuf *rlder_utf8(derb *db,uint8_t *q,int n)
{
  mbuf *bp;

  if(q == NULL || n < 0) return NULL;
  /* id(1)+len(3)+n+null(1) */
  if((bp=alloc_mbuf(4 + n + 1)) == NULL) return NULL;
  *bp->pc++ = 0x0C; /* utf8 */
  setlen(bp,n);
  memcpy(bp->pc,q,n);
  bp->pc += n;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append UTC time tin (secs) to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param tin time in time_t seconds from a time() call
    \return NULL if error; new mbuf filled in with DER UTC string otherwise
*/
mbuf *rlder_utctime(derb *db,time_t tin)
{
  mbuf *bp;
  struct tm *t,_t;

  /* 16 = one byte type + one byte length (13) 
   * + 13 bytes for UTC string + one byte trailing NULL 
   * for lazey display routines */
  if((bp=alloc_mbuf(16)) == NULL) return NULL;
  *bp->pc++ = 0x17; /* utc */
  setlen(bp,13);

  t = &_t;
  memcpy(t,gmtime(&tin),sizeof(struct tm));
  snprintf((char *)bp->pc,14,"%02u%02u%02u%02u%02u%02uZ",
          (t->tm_year+1900)%100,
          t->tm_mon + 1,
          t->tm_mday,
          t->tm_hour,
          t->tm_min,
          t->tm_sec);
  /*sprintf(bp->pc,"071228235959Z");*/

  bp->pc += 13;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append general time tin (secs) to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param tin time in time_t seconds from a time() call
    \return NULL if error; new mbuf filled in with DER generalized time otherwise
*/
mbuf *rlder_gentime(derb *db,time_t tin)
{
  mbuf *bp;
  struct tm *t,_t;

  /* 18 = one byte type + one byte length (15)
   * + 15 bytes for GENTIME string + one byte trailing NULL
   * for lazey display routines */
  if((bp=alloc_mbuf(18)) == NULL) return NULL;
  *bp->pc++ = 0x18; /* general time */
  setlen(bp,15);

  t = &_t;
  memcpy(t,gmtime(&tin),sizeof(struct tm));
  snprintf((char *)bp->pc,16,"%04u%02u%02u%02u%02u%02uZ",
          t->tm_year+1900,
          t->tm_mon + 1,
          t->tm_mday,
          t->tm_hour,
          t->tm_min,
          t->tm_sec);
  /*sprintf(bp->pc,"20071228235959Z");*/

  bp->pc += 15;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append rfc822 email address in ASCIIZ q to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param q ptr to ASCIIZ email string
    \return NULL if error; new mbuf filled in with DER email string otherwise
*/
mbuf *rlder_rfc822Name(derb *db,char *q)
{
  mbuf *bp;
  int n;

  if(q == NULL) return NULL;
  n = strlen(q);
  /* id(1)+len(3)+n+null(1) */
  if((bp=alloc_mbuf(4 + n + 1)) == NULL) return NULL;
  *bp->pc++ = 0x81; /* rfc822Name */
  setlen(bp,n);
  memcpy(bp->pc,q,n);
  bp->pc += n;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append keyidentifier (q,n) to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param q ptr to buffer with keyid
    \param n length of buffer above
    \return NULL if error; new mbuf filled in with DER keyidentifier otherwise
*/
mbuf *rlder_keyidentifier(derb *db,uint8_t *q,int n)
{
  mbuf *bp;

  if(q == NULL || n < 0) return NULL;
  /* id(1)+len(3)+n+null(1) */
  if((bp=alloc_mbuf(4 + n + 1)) == NULL) return NULL;
  *bp->pc++ = 0x80; /* key identifier */
  setlen(bp,n);
  memcpy(bp->pc,q,n);
  bp->pc += n;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append ASCIIZ generalname str to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param str ptr to ASCIIZ generalname
    \return NULL if error; new mbuf filled in with DER general name otherwise
*/
mbuf *rlder_generalname(derb *db,char *str)
{
  mbuf *bp;
  int n;

  if(str == NULL) return NULL;
  n = strlen(str);
  /* id(1)+len(3)+n+null(1) */
  if((bp=alloc_mbuf(4 + n + 1)) == NULL) return NULL;
  *bp->pc++ = 0x86; /* GeneralNames */
  setlen(bp,n);
  memcpy(bp->pc,str,n);
  bp->pc += n;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! append ASCIIZ ia5 str to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param str ptr to buffer with ASCIIZ IA5 string
    \return NULL if error; new mbuf filled in with DER IA5 string otherwise
*/
mbuf *rlder_ia5string(derb *db,char *str)
{
  mbuf *bp;
  int n;

  if(str == NULL) return NULL;
  n = strlen(str);
  /* id(1)+len(3)+n+null(1) */
  if((bp=alloc_mbuf(4 + n + 1)) == NULL) return NULL;
  *bp->pc++ = 0x16;
  setlen(bp,n);
  memcpy(bp->pc,str,n);
  bp->pc += n;
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}


/*
 * Common DER Contructed items
 */

/*! append OBJID+PRINTABLE STRING combo to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param obj ASCIIZ object ID
    \param str ASCIIZ printable string
    \return NULL if error; new mbuf filled in with DER element otherwise
*/
mbuf *rlder_pname(derb *db,char *obj,char *str)
{
  mbuf *bp0,*bp1;

  if(obj == NULL || str == NULL) return NULL;
  bp0 = rlder_start_set(db);
  bp1 = rlder_start_sequence(db);
  rlder_objid(db,obj);
  rlder_pstring(db,str);
  rlder_end_sequence(db,bp1);
  rlder_end_set(db,bp0);
  return bp0;
}

/*! append objid type dgst to mbuf chain in db 

    \param db work struct to accumulate DER elements
    \param dgst  ASCIIZ digest name
    \param param  Parameter
    \param paramlen Parameter length
    \return NULL if error; new mbuf filled in with DER element otherwise
*/
mbuf *rlder_dgstalg(derb *db,const char *dgst,uint8_t *param,int paramlen)
{
  mbuf *bp0;

  bp0 = rlder_start_sequence(db);
  rlder_objid(db,dgst);
  if(paramlen > 0) {
    if(param) rlder_octet(db,param,paramlen);
    else rlder_nullval(db);
  }
  rlder_end_sequence(db,bp0);
  return bp0;
}

/*! append series of digest algorithms separated by , in dgsts by objid to
    mbuf chain in db

    \param db work struct to accumulate DER elements
    \param dgsts comma separated ASCIIZ string of digest names
    \return NULL if error; new mbuf filled in with DER elements otherwise
*/
mbuf *rlder_dgstalgs(derb *db,char *dgsts)
{
  mbuf *bp0;
  char *p,*args[NARGS];
  int i,n;

  if(dgsts == NULL) return NULL;
  bp0 = rlder_start_set(db);
  p = strdup(dgsts);
  n = lparse(p,args,NARGS,',');
  for(i=0;i<n;i++) {
    rlder_dgstalg(db,args[i],NULL,1); /* Adobe uses ,0 = no NULL field */
  }
  rlder_end_set(db,bp0);
  free(p); /* nx2 */
  return bp0;
}


/*
 * Contruction utils
 *  Save response from "start_*" so that the corresponding "end_*" 
 *  routine can fill in the final length.
 */

/*! append begining of SEQUENCE to mbuf chain 

    \param db work struct to accumulate DER elements
    \return NULL if error; new mbuf with DER sequence otherwise
*/
mbuf *rlder_start_sequence(derb *db)
{
  mbuf *bp;
  /* id(1)+len(5) */
  if((bp=alloc_mbuf(6)) == NULL) return NULL; /* good up to 32-bit length */
  *bp->pc++ = 0x30; /* sequence */
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! fill in final length SEQUENCE 

    \param db work struct to accumulate DER elements
    \param bp ptr to mbuf of sequence header returned by above
    \return NULL if error; new mbuf with DER sequence otherwise
*/
int rlder_end_sequence(derb *db,mbuf *bp)
{
  int n;
  if(bp == NULL) return -1;
  n = mbuf_len(bp) - 1;
  setlen(bp,n);
  return 0;
}

/*! append begining of SET to mbuf chain 

    \param db work struct to accumulate DER elements
    \return NULL if error; new mbuf with DER set otherwise
*/
mbuf *rlder_start_set(derb *db)
{
  mbuf *bp;
  /* id(1)+len(5) */
  if((bp=alloc_mbuf(6)) == NULL) return NULL; /* good up to 32-bit length */
  *bp->pc++ = 0x31; /* set */
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! fill in final length SET 

    \param db work struct to accumulate DER elements
    \param bp ptr to mbuf of set header returned by above
    \return NULL if error; new mbuf with DER set otherwise
*/
int rlder_end_set(derb *db,mbuf *bp)
{
  int n;
  if(bp == NULL) return -1;
  n = mbuf_len(bp) - 1;
  setlen(bp,n);
  return 0;
}

/*! append begining of CONTENT to mbuf chain 

    \param db work struct to accumulate DER elements
    \param i content type 
    \return NULL if error; new mbuf with DER content otherwise
*/
mbuf *rlder_start_content(derb *db,int i)
{
  mbuf *bp;

  if(i >= 0x3F) {
    myx_syslog(LOG_ERR,"error: %s Invalid CONTENT [%d]\n",__func__,i);
    return NULL;
  }
  /* id(1)+len(5) */
  if((bp=alloc_mbuf(6)) == NULL) return NULL; /* good up to 32-bit length */
  *bp->pc++ = (0xA0 | i); /* content */
  if(db->bpN) db->bpN->next = bp;
  db->bpN = bp;
  return bp;
}

/*! fill in final length CONTENT 

    \param db work struct to accumulate DER elements
    \param bp ptr to mbuf of content header returned by above
    \return NULL if error; new mbuf with DER content otherwise
*/
int rlder_end_content(derb *db,mbuf *bp)
{
  int n;
  if(bp == NULL) return -1;
  n = mbuf_len(bp) - 1;
  setlen(bp,n);
  return 0;
}


/*
 * rudimentary DER decoder
 */
 
/*! decode and print a string or dump bytes 

    \param p ptr to DER struct to dump
    \param hexdmp 1 if binary 0 if ascii
    \return number of  bytes dumped
*/
static int dumpstr(uint8_t *p,int hexdmp)
{
  int i,n,len;

  /* skip idenifier */
  p++;
  n = 1;
  /* determine length */
  if((*p)&0x80) {
    i = (*p)&0x7F;
    p++;
    n++;
    if(i == 0) myx_syslog(LOG_INFO,"***indefinite len in %s\n",__func__);
    if(i == 1) {
      len = *p;
      p++;
      n++;
    } else { /* assume 2 */
      len = ((*p)<<8)|(*(p+1));
      p += 2;
      n += 2;
    }
  } else {
    len = *p;
    p++;
    n++;
  }
  myx_syslog(LOG_INFO,"len=%d ",len);
  if(hexdmp) rdump(p,len);
  else {
    for(i=0;i<len;i++) myx_syslog(LOG_INFO,"%c",p[i]);
    myx_syslog(LOG_INFO,"\n");
  }
  return (len + n);
}

/*! walk a DER struct and print contents - recursively

    \param db work struct
    \param p ptr to buffer with DER struct
    \param n number of bytes in buffer
    \return -1 if failed; 0 if ok.
*/
int rlder_derdec(derb *db,uint8_t *p,int n)
{
  int len,i,fno;
  char pad[50];

  if(p == NULL) {
    myx_syslog(LOG_ERR,"error: NULL content pointer at depth %d in %s\n",depth,__func__);
    return -1;
  }

  fno = 1;
  depth++;
  /*printf("%02d ",depth);*/
  for(i=0;i<depth;i++) pad[i] = ' ';
  pad[i] = '\0';
  /*printf("%sn = %d\n",pad,n);*/
  while(n > 0) {

    if((*p)&0x20) { /* constructed */
      switch(*p) {
      case 0x30: myx_syslog(LOG_INFO,"%sSEQUENCE\n",pad); break;
      case 0x31: myx_syslog(LOG_INFO,"%sSET\n",pad); break;
      case 0xA0: myx_syslog(LOG_INFO,"%sCONTENT [0]\n",pad); break;
      case 0xA1: myx_syslog(LOG_INFO,"%sCONTENT [1]\n",pad); break;
      case 0xA2: myx_syslog(LOG_INFO,"%sCONTENT [2]\n",pad); break;
      case 0xA3: myx_syslog(LOG_INFO,"%sCONTENT [3]\n",pad); break;
      case 0xA4: myx_syslog(LOG_INFO,"%sCONTENT [4]\n",pad); break;
      case 0xA5: myx_syslog(LOG_INFO,"%sCONTENT [5]\n",pad); break;
      case 0xA6: myx_syslog(LOG_INFO,"%sCONTENT [6]\n",pad); break;
      case 0xA7: myx_syslog(LOG_INFO,"%sCONTENT [7]\n",pad); break;
      default: myx_syslog(LOG_INFO,"%sUNKNOWN CONS\n",pad); break;
      }
      if(((*p)&0x1F) == 0x1F) {
        myx_syslog(LOG_INFO,">31 ");
        p++;
        n--;
        while((*p)&0x80) { p++; n--; }
      }
      p++;
      n--;
      if((*p)&0x80) { /* long len */
        i = (*p)&0x7F;
        p++;
        n--;
        if(i == 0) myx_syslog(LOG_INFO,"***indefinite len in %s\n",__func__);
        if(i == 1) {
          len = *p;
          p++;
          n--;
        } else { /* assume 2 */
          len = ((*p)<<8)|(*(p+1));
          p += 2;
          n -= 2;
        }
      } else {
        len = *p;
        p++;
        n--;
      }
      /*printf("%slen=%d\n",pad,len);*/
      rlder_derdec(db,p,len);
    } else { /* primitive */
      switch(*p) {
      case 0x00: myx_syslog(LOG_INFO,"%sEOC ",pad);
        len = 2;
        myx_syslog(LOG_INFO,"%s\n",(*(p+1))?"error: - non-zero eoc":" ");
        break;
      case 0x01: myx_syslog(LOG_INFO,"%sBOOLEAN ",pad);
        len = 3;
        myx_syslog(LOG_INFO,"%s\n",(*(p+2))?"TRUE":"FALSE");
        break;
      case 0x02: myx_syslog(LOG_INFO,"%sINTEGER ",pad); 
        len = dumpstr(p,1);
        break;
      case 0x03: myx_syslog(LOG_INFO,"%sBITSTRING ",pad);
        len = dumpstr(p,1);
        break;
      case 0x04: myx_syslog(LOG_INFO,"%sOCTET ",pad);
        len = dumpstr(p,1);
        break;
      case 0x13: myx_syslog(LOG_INFO,"%sPRINTABLESTRING ",pad);
        len = dumpstr(p,0);
        break;
      case 0x0C: myx_syslog(LOG_INFO,"%sUTF8 ",pad);
        len = dumpstr(p,0);
        break;
      case 0x17: myx_syslog(LOG_INFO,"%sUTCTIME ",pad);
        len = dumpstr(p,0);
        break;
      case 0x05: myx_syslog(LOG_INFO,"%sNULL\n",pad);
        len = 2;
        break;
      case 0x06: myx_syslog(LOG_INFO,"%sOBJID ",pad);
        /*len = dumpstr(p,1); */
        {
          struct oidtable *ids;
          len = *(p+1);
          for(ids=oids;ids->str;ids++) {
            if(len != ids->len) continue;
            if(memcmp(ids->data,(p+2),len)) continue;
            break;
          }
          if(ids->str) myx_syslog(LOG_INFO,"%s\n",ids->str);
          else {
            myx_syslog(LOG_INFO,"unk\n");
            rdump((p+2),len);
          }
          len += 2;
        }
        break;
      default: myx_syslog(LOG_INFO,"%sUNKNOWN PRIM ",pad);
        if(((*p)&0x1F) == 0x1F) {
          myx_syslog(LOG_INFO,">31 ");
          p++;
          while((*p)&0x80) p++;
        }
        len = dumpstr(p,1);
        break;
      }
    }
    p += len;
    n -= len;
    fno++;
  }
  depth--;
  return 0;
}


/*
 * Misc DER support
 */
 
/*! set the length in the begining of an mbuf buffer. sufficient space is
    pre-alloced by caller

    \param bp ptr to mbuf with a DER element
    \param n length to set the DER element to
    \return 0 if ok; -1 if error
*/
static int setlen(mbuf *bp,int n)
{
  if(n < 0x80) {
    *bp->pc++ = (uint8_t)n;
  } else if(n < 0x100) {
    *bp->pc++ = 0x81;
    *bp->pc++ = (uint8_t)n;
  } else if(n < 0x10000) {
    *bp->pc++ = 0x82; /* two byte length */
    *bp->pc++ = (uint8_t)(n >> 8);
    *bp->pc++ = (uint8_t)(n&0xFF);
  } else {
    myx_syslog(LOG_ERR,"error: %s\n",__func__);
    return -1;
  }
  return 0;
}

/*! create a flat mbuf with the DER element starting at p0.

   \param p0 pointer to DER element
   \return NULL if error; otherwise new mbuf containing duplicate DER element
 */
mbuf *rlder_dup_item(uint8_t *p0)
{
  mbuf *bp;
  uint8_t *p;
  int i,len,n;

  if(p0 == NULL) return NULL;
  n = 0;
  p = p0;
  if(((*p)&0x1F) == 0x1F) {
    p++;
    n++;
    while((*p)&0x80) { p++; n++; }
  }
  p++;
  n++;
  if((*p)&0x80) {
    i = (*p)&0x7F;
    p++;
    n++;
    if(i == 0) myx_syslog(LOG_INFO,"***indefinite len in %s\n",__func__);
    if(i == 1) {
      len = *p;

      n++;
    } else { /* assume 2 */
      len = ((*p)<<8)|(*(p+1));
      p += 2;
      n += 2;
    }
  } else {
    len = *p;

    n++;
  }
  len += n;

  if((bp=alloc_mbuf(len)) == NULL) return NULL;
  memcpy(bp->p0,p0,len);
  bp->pc += len;

  return bp;
}

/***************************************************************
 * end
 ***************************************************************/
