/*
 * $Id: mbuf.h 95 2010-03-25 20:15:22Z jakob $
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

#ifndef _MBUF_H_
#define _MBUF_H_

#include <stdint.h>
#include <stdio.h>

typedef struct _mbuf {
  struct _mbuf *next;
  uint8_t *p0,*pc;
} mbuf;

/* compat */
#define alloc_mbuf(n) mbuf_alloc(n)

mbuf *mbuf_alloc(int n);
void mbuf_free(mbuf *bp);
int mbuf_len(mbuf *bp0);
mbuf *mbuf_dup(mbuf *bp0);
mbuf *mbuf_flat(mbuf *bp0);
void mbuf_dump(mbuf *bp0);
int mbuf_out(mbuf *bp,FILE *fp);
mbuf *buf2mbuf(uint8_t *p,int n);
mbuf *file2mbuf(char *fname);

#endif /* _MBUF_H_ */
