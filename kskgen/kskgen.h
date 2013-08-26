/*
 * $Id: kskgen.h 297 2010-05-27 02:25:56Z lamb $
 *
 * Copyright (C) 2009 Internet Corporation for Assigned Names
 *                         and Numbers (ICANN)
 *                            and
 * Copyright (C) 2006, 2007 Richard H Lamb (RHL)
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ICANN+RHL DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ICANN+RHL BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Based on
 * "IANA DNSSEC Signed Root Testbed Project,Copyright (C) ICANN 2007,2008,2009"
 * and
 * "Netwitness.org/net Standalone PKCS#7 Signer,Copyright (C) RHLamb 2006,2007"
 *
 * Author: RHLamb
 */

#ifndef _KSKGEN_H_
#define _KSKGEN_H_

extern int debug;

typedef struct {
  /* dnssec */
  char dn[256]; /* domain name */
  int alg;
  int flags;
  int proto;
  char dnskey[4096]; /* dnssec pubkey fmt */
  char ds1[128]; /* DS sha1 */
  char ds2[128]; /* DS sha256 */
  mbuf *ds2bp;
  int tag;

  /* x509 */
  mbuf *pkcspub; /* pkcs pubkey fmt */
  int htype; /* hash type */
  const char *dgstalg,*dgstalg2; /* OIDs */
  mbuf *distinguishedname;
  char *email;

  /* pkcs11 */
  mbuf *label;
  void *pkcb;
} kcrecord;

#endif /* _KSKGEN_H_ */
