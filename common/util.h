/*
 * $Id: util.h 564 2010-10-25 06:44:08Z jakob $
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

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "mbuf.h"

#define PEM_LINE_LENGTH 64
#define LBUFLEN MAXPATHLEN
#define min(x,y) ((x)<(y)?(x):(y))
#define max(x,y) ((x)>(y)?(x):(y))

#define PGPWORDLIST_BEGIN ">> "
#define PGPWORDLIST_END   " <<"

typedef struct {
  char *ctx;
#define HASH_SHA1    1
#define HASH_SHA256  2
  int type;
} genhashctx;
int hashit(genhashctx *gh,uint8_t *buf,int len);
int hashfile(FILE *fp,int htype,uint8_t *dgst);

mbuf *pgp_wordlist2(const uint8_t *hash,int hashlen);

int str_cleanup(char *io);
uint32_t atoul(const char *str);
int hex2i(char c);
int lparse(char *line,char *argv[],int maxargs,char delc);

int base64encode(char *out, size_t outlen, const uint8_t *in,int n);
int base64decode(const char *in,uint8_t *out, size_t outlen);
void gmtstrtime(time_t ltmp,char *str);
void sec2ztime(time_t zsec,char *str);
int hdump(const uint8_t *ptr,int n);
int rdump(const uint8_t *ptr,int n);
const char *randomstring();

#endif /* _UTIL_H_ */
