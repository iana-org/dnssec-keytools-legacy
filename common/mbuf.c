/*
 * $Id: mbuf.c 324 2010-05-27 21:12:36Z jakob $
 *
 * Copyright (C) 2006, 2007 Richard H. Lamb (RHL). All rights reserved.
 *
 * Based on
 * "Netwitness.org/net Standalone PKCS#7 Signer,Copyright (C) RHLamb 2006,2007"
 * and other libraries Copyright (C) RHLamb 1995-2007
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND RHL DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL RHL BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Author: RHLamb
 */

#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#include "mbuf.h"
#include "logger.h"

static char *_mbuf_calloc(int n,int j)
{
  char *p;

  if((p=calloc(n,j)) == NULL) {
    logger_fatal("Can not calloc(%d,%d) memory in %s\n",n,j,__func__);
  }
  return p;
}

/* return a zeroed n byte long mbuf
   caller must call mbuf_free() */
mbuf *
mbuf_alloc(int n)
{
  mbuf *bp;

  if(n < 0) return NULL;
  bp = (mbuf *)_mbuf_calloc(1, sizeof(mbuf) + n);
  if(bp) {
    bp->p0 = bp->pc = (uint8_t *)(bp+1);
  }
  return bp;
}

/* free an mbuf */
void mbuf_free(mbuf *bp)
{
  if(bp == NULL) return;
  memset(bp,0xAA,sizeof(mbuf) + (int)(bp->pc - bp->p0));/*catch bugs*/
  free(bp);
}

/* return the total length of an mbuf chain starting at bp0 */
int
mbuf_len(mbuf *bp0)
{
  mbuf *bp;
  int n;

  if(bp0 == NULL) return -1;
  n = 0;
  for(bp=bp0;bp;bp=bp->next) n += (int)(bp->pc - bp->p0);
  return n;
}

/* return a flat (single) duplicate of mbuf chain bp0 */
mbuf *
mbuf_dup(mbuf *bp0)
{
  mbuf *bp,*bp1;
  int n;

  n = mbuf_len(bp0);
  if((bp1=alloc_mbuf(n)) == NULL) return NULL;
  for(bp=bp0;bp;bp=bp->next) {
    n = (int)(bp->pc - bp->p0);
    memcpy(bp1->pc,bp->p0,n);
    bp1->pc += n;
  }
  return bp1;
}

/* return a flat (single) mbuf version of bp0 - freeing bp0 */
mbuf *
mbuf_flat(mbuf *bp0)
{
  mbuf *bp,*bpn,*bp1;
  int n;

  n = mbuf_len(bp0);
  if((bp1=alloc_mbuf(n)) == NULL) return NULL;
  for(bp=bp0;bp;) {
    n = (int)(bp->pc - bp->p0);
    memcpy(bp1->pc,bp->p0,n);
    bp1->pc += n;
    bpn = bp->next;
    mbuf_free(bp);
    bp = bpn;
  }
  return bp1;
}

/* output contents of mbuf chain bp0 to a open file referenced by fp */
int
mbuf_out(mbuf *bp0,FILE *fp)
{
  mbuf *bp;
  int n,j;

  if(bp0 == NULL || fp == NULL) return -1;
  j = 0;
  for(bp=bp0;bp;bp=bp->next) {
    n = (int)(bp->pc - bp->p0);
    j += fwrite(bp->p0,1,n,fp);
  }
  return j;
}

/* return a mbuf with contents (p,n) */
mbuf *
buf2mbuf(uint8_t *p,int n)
{
  mbuf *bp;

  if((bp=alloc_mbuf(n)) == NULL) return NULL;
  memcpy(bp->p0,p,n);
  bp->pc += n;
  return bp;
}

/* return an mbuf filled with the contents fo fname */
mbuf *
file2mbuf(char *fname)
{
  struct stat st;
  mbuf *bp;
  int n;
  FILE *fp;

  if(stat(fname,&st)) return NULL;
  if((fp=fopen(fname,"rb")) == NULL) return NULL;
  if((bp=alloc_mbuf(st.st_size)) == NULL) {
    fclose(fp);
    return NULL;
  }
  n = fread(bp->pc,1,st.st_size,fp);
  fclose(fp);
  if(n < st.st_size) {
    mbuf_free(bp);
    return NULL;
  }
  bp->pc += n;
  return bp;
}
