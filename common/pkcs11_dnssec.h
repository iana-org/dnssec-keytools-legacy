/*
 * $Id: pkcs11_dnssec.h 564 2010-10-25 06:44:08Z jakob $
 *
 * Copyright (c) 2010 Internet Corporation for Assigned Names ("ICANN")
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

#ifndef _PKCS11_DNSSEC_H_
#define _PKCS11_DNSSEC_H_

#include "cryptoki.h"
#include "mbuf.h"

/*! Default path to HSM configuration */
#define PKCS11_HSMCONFIGDIR       "/opt/dnssec"

/*! Default PIN */
#define PKCS11_DEFAULT_PIN        "123456"

#define PKCS11_MAX_SLOTS          100   /*!< Max number of HSM slots */
#define PKCS11_MAX_KEYS_PER_SLOT  1000  /*!< Max number of keys per HSM slot */


/*! per HSM slot control block */
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

/*! per pkcs11 key control block */
typedef struct {
  mbuf *modulus;  /*!< CKA_MODULUS */
  mbuf *pubexp;   /*!< CKA_PUBLIC_EXPONENT */
  int bits;
  mbuf *label;    /*!< CKA_LABEL */
  mbuf *id;       /*!< CKA_ID */
  void *pk;       /*!< pkcs11 per slot cb */
  void *hk;       /*!< pub key handle */
  void *hkp;      /*!< priv key handle */
} pkkeycb;


int pkcs11_bits(void *vkr);
mbuf *pkcs11_modulus(void *vkr);
mbuf *pkcs11_pubexp(void *vkr);
mbuf *pkcs11_label(void *vkr);
int pkcs11_have_private_key(void *vkr);
void pkcs11_free_pkkeycb(void *vkr);

/*! Initializate PKCS#11 library

\param otherdir  Alternate directory to scan for HSM configuration
\return 0 upon success, otherwise error code 

*/
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

#endif /* _PKCS11_DNSSEC_H_ */
