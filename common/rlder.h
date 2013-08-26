/*
 * $Id: rlder.h 564 2010-10-25 06:44:08Z jakob $
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

#ifndef _RLDER_H_
#define _RLDER_H_

#include <time.h>
#include <stdint.h>

#include "mbuf.h"

typedef struct {
  mbuf *bpN; /* last mbuf in chain */
} derb;

mbuf *rlder_dgstalg(derb *db,const char *dgst,uint8_t *param,int paramlen);
mbuf *rlder_dgstalgs(derb *db,char *dgsts);

mbuf *rlder_start_sequence(derb *db);
mbuf *rlder_start_set(derb *db);
mbuf *rlder_start_content(derb *db,int i);
int rlder_end_sequence(derb *db,mbuf *bp);
int rlder_end_set(derb *db,mbuf *bp);
int rlder_end_content(derb *db,mbuf *bp);
mbuf *rlder_rfc822Name(derb *db,char *q);
mbuf *rlder_keyidentifier(derb *db,uint8_t *q,int n);
mbuf *rlder_generalname(derb *db,char *str);
mbuf *rlder_ia5string(derb *db,char *str);

mbuf *rlder_integer(derb *db,int n);
mbuf *rlder_binteger(derb *db,uint8_t *q,int n);
mbuf *rlder_objid(derb *db,const char *idstr);
mbuf *rlder_bitstring(derb *db,uint8_t *q,int n);
mbuf *rlder_octet(derb *db,uint8_t *q,int n);
mbuf *rlder_utf8(derb *db,uint8_t *q,int n);
mbuf *rlder_utctime(derb *db,time_t tin);
mbuf *rlder_gentime(derb *db,time_t tin);
mbuf *rlder_nullval(derb *db);
mbuf *rlder_pname(derb *db,char *obj,char *str);
mbuf *rlder_pstring(derb *db,char *str);
mbuf *rlder_booleanv(derb *db,int tf);
mbuf *rlder_eoc(derb *db);

mbuf *rlder_dup_item(uint8_t *p);

#endif /* _RLDER_H */
