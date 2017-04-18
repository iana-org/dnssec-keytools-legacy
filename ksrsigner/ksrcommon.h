/*
 * $Id: ksrcommon.h 566 2010-10-27 20:12:05Z jakob $
 *
 * Copyright (c) 2007 Internet Corporation for Assigned Names ("ICANN")
 *
 * Author: Richard H. Lamb ("RHL") richard.lamb@icann.org
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

#ifndef _KSRCOMMON_H_
#define _KSRCOMMON_H_

typedef struct _krecord {
  struct _krecord *next;

  /* dnssec */
  char *keyIdentifier;
  uint16_t keyTag;

  uint32_t TTL;
  uint16_t Flags;
  uint8_t Protocol;
  uint8_t Algorithm;
  char *PublicKey;

  void *user;
  int signer; /* 1 = use to sign bundle */

  /* copies of pkcs11 for code readability */
  mbuf *modulus;
  mbuf *pubexp;
  mbuf *label;
  int bits;

  /* pkcs11 */
  void *pkcb;
} krecord;

typedef struct{
  uint8_t *w;
  int len;
  uint8_t *rdata;
  int rdatalen;
} wirerr;

typedef struct _signer {
  struct _signer *next;
  /* 
   * Unique identifier across HSM's and slots 
   * format Kxxxxx where "xxxxx" is the DNSSEC
   * key tag (alg=8,proto=3,flags=257) identifying 
   * the KSK.
   */
  char *keyIdentifier;
} signer;

typedef struct _signature {
  struct _signature *next;
  char *keyIdentifier;

  uint32_t TTL;
  char *TypeCovered;
  uint8_t Algorithm;
  uint8_t Labels;
  uint32_t OriginalTTL;
  time_t SignatureExpiration;
  time_t SignatureInception;
  uint16_t KeyTag;
  char *SignersName;
  char *SignatureData;
} signature;

typedef struct _sigalg {
  struct _sigalg *next; // Add multiple SignatureAlgorithm support
  int algorithm;
  int rsa_size;
  int rsa_exp;
} sigalg;

typedef struct {
  char *PublishSafety;
  char *RetireSafety;
  char *MaxSignatureValidity;
  char *MinSignatureValidity;
  char *MaxValidityOverlap;
  char *MinValidityOverlap;
  sigalg *sigalg;
} responsepolicy;

typedef struct _reqresp {
  char *id;
  int response;
  time_t Expiration,Inception; /* un-validated */

  krecord *x_key;
  signature *x_sig;
  signer *x_sgr;

  time_t expmax,incmin; /* latest VALIDATED expiration/inception */
} reqresp;

#define MAX_BUNDLES 10 /* max of 90days split in 10 day bundles */
#define MAX_KSKS 100
#define MAX_ZSKS 10
#define MAX_KEYS (MAX_KSKS+MAX_ZSKS)

typedef struct {
  FILE *fin;
  int depth;
  int shorttag;

  char *ksrserial,*ksrid,*ksrdomain;
  reqresp *rqrs[MAX_BUNDLES];
  int rqrscnt;

} xmlstate;

/*
 * these were all static.  hopefully unstaticing them does not cause confusion
 * From ksrcommon.c 
 */
int dndepth(char *dn);
int algtohash(int alg);
int xmlparse(char *tp,xmlstate *xs);
void free_requestresponse(reqresp *rq);
int expmaxcmpr(const void *a,const void *b);
int signem(FILE *ftmp,xmlstate *xs);
void display_reqresp(reqresp *rq[],int cnt);
int check_requestbundle(reqresp *rq,char *domain);
int check_responsebundle(reqresp *rq);
void free_keyrecord(krecord *kr);

/* specific to wksr and ksrsigner */
int validatekeybundle(signature *s,krecord *klist);
int rrsig(krecord *keys[],int keycnt,char *dn,time_t t_inception,time_t t_expiration,int *showkeys,FILE *ftmp);

/* these were all static */
extern char *ksklabel_1,*ksklabel_2;
extern time_t t_step,validityperiod,maxexpiration;

extern krecord *ksks[MAX_KSKS];
extern int nksk;

extern int ksrinvalid;

extern int revoke_all;

/* this was not */
extern int debug;

/* json key schedule parsing support */

#define JSONKSCHEDULEFILE "kskschedule.json"
typedef struct _kskslot {
  struct _kskslot *next;
  int seq;
  int n_pub,n_revoke,n_sign;
#define JSON_NKEYS 5
  char *cka_label_pub[JSON_NKEYS];
  char *cka_label_sign[JSON_NKEYS];
  char *cka_label_revoke[JSON_NKEYS];
} kskslot;
typedef struct _kskschedule {
  struct _kskschedule *next;
  char *name;
  kskslot *s;
} kskschedule;
static kskschedule *ksksch0=NULL;
int loadkeyschedule(void);

#endif /* _KSRCOMMON_H_ */
