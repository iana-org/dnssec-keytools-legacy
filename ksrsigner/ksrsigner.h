/*
 * $Id: ksrsigner.h 564 2010-10-25 06:44:08Z jakob $
 *
 * Copyright (c) 2007 Internet Corporation for Assigned Names ("ICANN")
 * Copyright (c) 2006 Richard H. Lamb ("RHL") slamb@xtcn.com
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

#ifndef _KSRSIGNER_H_
#define _KSRSIGNER_H_

extern int debug;

typedef struct _krecord {
  struct _krecord *next;
  char *keyIdentifier;
  uint16_t keyTag;

  uint32_t TTL;
  uint16_t Flags;
  uint8_t Protocol;
  uint8_t Algorithm;
  char *PublicKey;

  void *user;
  int signer; /* 1 = use to sign bundle */

  /*****/
  mbuf *modulus;
  mbuf *pubexp;
  int bits;
  mbuf *label;
  mbuf *id;
  void *pk; /* hsm-slot */
  void *hk; /* handle for public key in above slot */
  void *hkp; /* have private key */
} krecord;

int fillinkinfo(krecord *kr);

mbuf *pkcs1padrsa(int htype,uint8_t *hash,int hashlen,int klen);

typedef struct{
  uint8_t *w;
  int len;
  uint8_t *rdata;
  int rdatalen;
} wirerr;

extern char *ksrserial,*ksrid,*ksrdomain;
extern char *ksklabel_1,*ksklabel_2,*ksrfile,*skrfile;
extern time_t t_step,validityperiod,maxexpiration;
extern uint32_t DefaultTTL;
extern krecord *ksks[MAX_KSKS];
extern int nksk;
extern reqresp *resps[MAX_BUNDLES];
extern int respscnt;
extern reqresp *reqs[MAX_BUNDLES];
extern int reqscnt;
extern int ksrinvalid=0;
extern int override_chain=0;
extern char skr_keybundle_template[MAXPATHLEN];
extern int testitbcnt=0;

#endif /* _KSRSIGNER_H_ */
