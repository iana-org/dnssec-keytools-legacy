/*
 * $Id: mbuf.c 567 2010-10-28 05:11:10Z jakob $
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

#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#include "mbuf.h"
#include "logger.h"

/*! Since we have litte recourse but to exit on a failed memory allocation,
    wrap the allocation call with fatal exit should memory alloc fail.

    \param n number of elements of size j
    \param j size of each element
    \return ptr to zeroed new buffer; otherwise does not return.
 */
static char *_mbuf_calloc(int n,int j)
{
  char *p;

  if((p=calloc(n,j)) == NULL) {
    logger_fatal("Can not calloc(%d,%d) memory in %s\n",n,j,__func__);
  }
  return p;
}

/*! return a zeroed n byte long mbuf caller must call mbuf_free() 

    \param n size of mbuf
    \return NULL if fail; ptr to new zeroed mbuf if ok
 */
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

/*! free an mbuf by first writing pattern to space to try to catch bugs

    \param bp ptr to mbuf to free
 */
void mbuf_free(mbuf *bp)
{
  if(bp == NULL) return;
  memset(bp,0xAA,sizeof(mbuf) + (int)(bp->pc - bp->p0));/*catch bugs*/
  free(bp);
}

/*! return the total length of an mbuf chain starting at bp0 

   \param bp0 ptr to mbuf to calculate the total chained length of.
   \return -1 if failed; otherwise total number of bytes in this mbuf chain.
*/
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

/*! return a flat (single) duplicate of mbuf chain bp0. Does NOT free original

    \param bp0 ptr to mbuf chain to duplicate.
    \return NULL if failed; ptr to new duplicate single mbuf otherwise
 */
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

/*! return a flat (single) mbuf version of bp0 - freeing bp0 

    \param bp0 ptr to mbuf chain to duplicate
    \return NULL if failed; ptr to new duplicate single mbuf otherwise
 */
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

/*! output contents of mbuf chain bp0 to a open file referenced by fp 

    \param bp0 ptr to mbuf chain to binary dump to file
    \param fp open file ptr to write binary data to
    \return NULL if failed; number of bytes written otherwise
 */
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

/*! return a mbuf with contents (p,n) 

    \param p ptr to buffer with data to be copied to the new mbuf
    \param n number of bytes from p to copy to new mbuf
    \return NULL if failed; otherwise ptr to new mbuf with a copy of n bytes from p
 */
mbuf *
buf2mbuf(uint8_t *p,int n)
{
  mbuf *bp;

  if((bp=alloc_mbuf(n)) == NULL) return NULL;
  memcpy(bp->p0,p,n);
  bp->pc += n;
  return bp;
}

/*! return an mbuf filled with the contents fo fname 

    \param fname filename whose binary contents will be loaded into a mbuf
    \return NULL if failed; mbuf filled with contents if ok.
 */
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
