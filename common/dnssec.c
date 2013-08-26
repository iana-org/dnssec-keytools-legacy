/*
 * $Id: dnssec.c 567 2010-10-28 05:11:10Z jakob $
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

#include <string.h>

#include "dnssec.h"

uint16_t dnssec_keytag (const uint8_t *key, size_t klen)
{
  uint32_t acm;
  int i;

  for(acm=0,i=0;i<(int)klen;++i) acm += (i&1)?key[i]:(key[i]<< 8);
  acm += (acm>>16)&0xFFFF;
  return acm&0xFFFF;
}

size_t dnssec_dn2wire(const char *dn, uint8_t *wire)
{
  size_t n;
  uint8_t *p,*q,*q0;

  if(strcmp(dn,".") == 0) {
    wire[0] = '\0';
    return 1;
  }

  q0 = wire;
  q = q0 + 1;
  n = 0;

  for(p=(uint8_t *)dn;*p;p++) {
    if(*p == '.') {
      *q0 = (uint8_t)n;
      q0 += (n+1);
      q = q0 + 1;
      n = 0;
      continue;
    }
    *q++ = *p;
    n++;
  }

  *q0 = (uint8_t)n;
  q0 += (n+1);
  n = (int)(q0 - wire);

  return n;
}
