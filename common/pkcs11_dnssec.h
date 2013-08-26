/*
 * $Id: pkcs11_dnssec.h 376 2010-05-30 01:06:11Z lamb $
 *
 * Copyright (C) 2010 Internet Corporation for Assigned Names
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _PKCS11_DNSSEC_H_
#define _PKCS11_DNSSEC_H_

#include "cryptoki.h"
#include "mbuf.h"

#define PKCS11_HSMCONFIGDIR "/opt/dnssec"
#define PKCS11_DEFAULT_PIN        "123456"
#define PKCS11_MAX_SLOTS          100
#define PKCS11_MAX_KEYS_PER_SLOT  1000

int pkcs11_bits(void *vkr);
mbuf *pkcs11_modulus(void *vkr);
mbuf *pkcs11_pubexp(void *vkr);
mbuf *pkcs11_label(void *vkr);
int pkcs11_have_private_key(void *vkr);
void pkcs11_free_pkkeycb(void *vkr);
int pkcs11_init(char *otherdir);
void pkcs11_close(void *vpk);
int pkcs11_cbsize();
int pkcs11_hsmverify(mbuf *modulus,mbuf *pubexp,uint8_t *sig,int siglen,uint8_t *data,int datalen);
int pkcs11_getpub(char *label,char *id,mbuf *mod,mbuf *exp,void *vdc[],int kmax);
int pkcs11_rsasignit2(void *vkr,uint8_t *data,int datalen,uint8_t *sout,int *slen);
mbuf *pkcs11_pkcssign(mbuf *bp,void *vdc);
mbuf *pkcs11_getcert(void *vdc);
void *pkcs11_genrsakey(int bits,int flags);
int pkcs11_delkey(void *vdc);


/* per HSM slot control block */
typedef struct {
  char *hsmconfig;
  char *lib;
  void *hLib;
  CK_FUNCTION_LIST_PTR pfl;
  CK_SESSION_HANDLE sh;
  int loggedin;
  int slot;

  /*
   * null:no login needed
   * nonnull+zerolen:interactive pin
   * nonzero len:has pin in it
   */   
   char *pin;
} pkcs11cb;

/* per pkcs11 key control block */
typedef struct {
  mbuf *modulus; /* CKA_MODULUS */
  mbuf *pubexp; /* CKA_PUBLIC_EXPONENT */
  int bits;
  mbuf *label; /* CKA_LABEL */
  mbuf *id; /* CKA_ID */
  void *pk; /* pkcs11 per slot cb */
  void *hk; /* pub key handle */
  void *hkp; /* priv key handle */
} pkkeycb;


#endif /* _PKCS11_DNSSEC_H_ */
