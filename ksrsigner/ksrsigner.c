/*
 * $Id: ksrsigner.c 567 2010-10-28 05:11:10Z jakob $
 *
 * Copyright (c) 2007 Internet Corporation for Assigned Names ("ICANN")
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

#include "config.h"
#include "util.h"
#include "logger.h"
#include "ksrcommon.h"
#include "ksrpolicy.h"
#include "pkcs11_dnssec.h"
#include "dnssec.h"
#include "compat.h"

#define LOGDIR "."  /*!< Directory for logfiles */

static const char *progname = "ksrsigner";

/*
 * These were cleaner and safer and best left static 
 * Tradeoff for readability
 */
char *ksklabel_1,*ksklabel_2;
time_t t_step,validityperiod,maxexpiration;

krecord *ksks[MAX_KSKS];
int nksk;

int ksrinvalid=0;

int revoke_all=0;

int debug=0;

static uint32_t DefaultTTL;
static int override_chain=0;
static char skr_keybundle_template[MAXPATHLEN];
static int testitbcnt=0;
static char *ksrfile = NULL,*skrfile = NULL;
static char nowstr[30];
static time_t t_now;

static int getKSKs(krecord *ksks[]);

/*! ksrsigner main

    Usage: ksrsigner [current-KSK] [next-KSK]
     /w no arguments, will sign ksr.xml with first found or KSR requested ones
     /w one argument, use that KSK
     /w two arguments, use the first and rollover to second

    -Override skips required match with prior KSR/SKR in chain.

    -Revoke creates a SKR that sets the REVOKE bit for all KSK, i.e., for
    reverting to insecure and unsigned.

    \param argc argtument count
    \param *argv[] pointer to args described above
    \return 0 on success, non-zero on error
*/
int main(int argc,char *argv[])
{
  FILE *fin,*ftmp,*fout;
  xmlstate _xs,*xs;
  xmlstate _xss,*xss;
  int i,ret,hashlen;
  uint8_t hash[1024];
  char *p, lbuf[MAXPATHLEN];
  char lbuf2[MAXPATHLEN]; /* just for skr renaming below */
  char *skrold=NULL;

  ret = -1;

  for(i=1;i<argc;i++) {
    if(strcmp(argv[i],"-V") == 0) {
      printf("%s %s version %s\n", PACKAGE_TARNAME, progname, PACKAGE_VERSION);
      exit(0);
    }

    if(strcmp(argv[i],"-d") == 0) { debug = 1; continue; } // Added a debug flag for testing
    
    if(strcmp(argv[i],"-h") == 0) {
      printf("Usage: %s [-Override] [-Revoke] [-h] [current-KSK] [next-KSK] [KSR-to-sign.xml]\n", argv[0]);
      printf("  - with no arguments, will sign %s with all or KSR requested KSKs\n",DEFAULT_KSR_FILENAME);
      printf("  - with one argument, use that KSK\n");
      printf("  - with two arguments, use the first and rollover to second\n");
      printf("-Override overrides check against last valid SKR - BEWARE\n");
      printf("-Revoke revokes all KSKs - BEWARE\n");
      printf("-h generates this message.\n");
      printf("If a file is specified /w a .xml suffix, it will be used as the KSR instead\n");
      printf("of the default %s in the current directory.\n",DEFAULT_KSR_FILENAME);
      printf("The SKR will be put in the same directory as the KSR but prefixed with skr.\n");
      return -1;
    }
    
    /* use the first argv[] that ends in .xml as the KSR and derive the 
       SKR path name from this as well */
    if(ksrfile == NULL 
       && (p=strrchr(argv[i],'.')) 
       && strcmp(p,".xml") == 0) {
      char *ksrpath;

      ksrfile = strdup(argv[i]); /* CVTY - maybe quiet complaints */
      ksrpath = strdup(ksrfile);
      if((p=strrchr(ksrpath,'/'))) {
        *p++ = '\0';
      } else {
        strlcpy(ksrpath,".",strlen(ksrpath));
        p = ksrfile;
      }
      if(strncasecmp(p,"ksr",3) == 0) {
	/*! if it starts with "ksr", just change "ksr" to "skr" */
        snprintf(lbuf,sizeof(lbuf),"%s/skr%s",ksrpath,&p[3]);
      } else {
	/*! otherwise prefix the ksr filename with "skr" */
        snprintf(lbuf,sizeof(lbuf),"%s/skr-%s",ksrpath,p);
      }
      skrfile = strdup(lbuf);
      snprintf(lbuf,sizeof(lbuf),"%s/%s",ksrpath,DEFAULT_SKR_FILENAME);
      skrold = strdup(lbuf);
      free(ksrpath);
      continue;
    }
    /* From key ceremony rehearsals can specify -OceRidE or just -O */
    if(strncmp(argv[i],"-O",2) == 0) { override_chain = 1; continue; }
    if(strncmp(argv[i],"-R",2) == 0) { revoke_all = 1; continue; }
    if(ksklabel_1 == NULL) { ksklabel_1 = strdup(argv[i]); continue; }
    if(ksklabel_2 == NULL) { ksklabel_2 = strdup(argv[i]); continue; }
  }

  /* Make sure we have some resonable defaults if magic above fails */
  if(ksrfile == NULL) ksrfile = strdup(DEFAULT_KSR_FILENAME);
  if(skrfile == NULL) skrfile = strdup(DEFAULT_SKR_FILENAME);
  if(skrold == NULL) skrold = strdup(DEFAULT_SKR_FILENAME);

  /* Note current time */
  time(&t_now);
  gmtstrtime(t_now, nowstr);

  /* Init log system and say hello to the auditors */
  logger_init(progname, LOGDIR, LOG_STDOUT);
  logger_hello(argc, argv);  

  maxexpiration = t_now + (T_VLIMIT*T_ONEDAY);
  DefaultTTL = T_DEFAULT_TTL;
  t_step = T_STEP*T_ONEDAY;
  validityperiod = T_VALIDITY*T_ONEDAY;

  mkdir("tmp",0777);
  snprintf(skr_keybundle_template,sizeof(skr_keybundle_template),"tmp/skr.keybundle.%%d");

  xs = &_xs;
  memset(xs,0,sizeof(xmlstate));
  xss = &_xss;
  memset(xss,0,sizeof(xmlstate));

  /*
   * Activate HSM
   */
  if(pkcs11_init(PKCS11_HSMCONFIGDIR)) goto end;

  /* 
   * get HSM key data 
   */
  if((nksk=getKSKs(ksks)) <= 0) {
    logger_error("Cannot find any KSKs to sign with");
    goto end;
  }

  /*
   * Verify SKR[n-1] KSK RRSIGs using matching private KSK in HSM
   */
  if(override_chain) {
    logger_info("Overriding match with last SKR...");
    logger_info("");
    goto ksr_validate;
  }
  logger_info("Validating last SKR with HSM...");

  ksrinvalid = 0;

  if((fin=fopen(skrold,"r")) == NULL) {
    logger_error("Cannot open last KSR response file %s",skrold);
    logger_error("If this is first KSR, you may want to override with -Override if authorized.");
    goto end;
  }

  /* parse SKR */
  xss->fin = fin;
  xmlparse("",xss);
  fclose(fin);

  if(xss->rqrscnt <= 0) {
    logger_error("No KSR responses found in SKR");
    goto end;
  }
  if(debug && xss->rqrscnt > 3) {
    logger_warning("More than 3 (early,on-time,late) key sets in KSR response");
  }
  qsort((void *)xss->rqrs,xss->rqrscnt,sizeof(void *),expmaxcmpr);
  display_reqresp(xss->rqrs,xss->rqrscnt);

  /* check policies of SKR */
  for(i=0;i<xss->rqrscnt;i++) {
    check_responsebundle(xss->rqrs[i]);
  }
  if(ksrinvalid) goto end;

  logger_info("...VALIDATED.");
  logger_info("");


  /*
   * Validate KSR[n] and create response
   */
 ksr_validate:
  logger_info("Validate and Process KSR %s...",ksrfile);

  if((fin=fopen(ksrfile,"r")) == NULL) {
    logger_error("Cannot open input file %s",ksrfile);
    goto end;
  }

  ksrinvalid = 0;

  /* parse KSR */
  xs->fin = fin;
  xmlparse("",xs);
  rewind(fin);
  hashlen = hashfile(fin,HASH_SHA256,hash);
  fclose(fin);

  if(xs->rqrscnt <= 0) {
    logger_error("No KSR requests found in KSR");
    goto end;
  }  
  if(debug && xs->rqrscnt > 3) {
    logger_warning("More than 3 (early,on-time,late) key sets in KSR request");
  }
  qsort((void *)xs->rqrs,xs->rqrscnt,sizeof(void *),expmaxcmpr);
  display_reqresp(xs->rqrs,xs->rqrscnt);

  /* check policies of KSR */
  for(i=0;i<xs->rqrscnt;i++) {
    check_requestbundle(xs->rqrs[i],xs->ksrdomain);
  }
  /*
   * Check that this KSR is part of the chain
   *  SKR[n-1]ZSK[0] == KSR[n]ZSK[-] ?
   *  SKR[n-1]ZSK[+] == KSR[n]ZSK[0] ?
   * SKR[n-1] = last skr verified above.
   * KSR[n] = this KSR
   * ZSK[x] = ZSK in SKR or KSR. 
   *  0 = used throughout, + = new one, - = old one.
   */
  if(override_chain == 0) {
    reqresp *rq,*rs;
    krecord *y,*x,*skrk[3],*ksrk[3];
    int j,k;

    k = 0;
    rs = xss->rqrs[xss->rqrscnt - 1];
    rq = xs->rqrs[0];
    for(y=rs->x_key,i=0;y && i<2;y=y->next) {
      if((y->Flags & DNSKEY_SEP_FLAG)) continue;
      skrk[i++] = y;
    }
    for(x=rq->x_key,j=0;x && j<2;x=x->next) ksrk[j++] = x;
    if(i != 2) {
      // Change for 1024->2048 ZSK fallback path KSRs. Error is now warning
      logger_warning("Wrong number (%d) of ZSKs in SKR",i);
    }
    if(j != 2) {
      // Changed for 1024->2048 ZSK fallback path KSRs. Error is now warning
      logger_warning("Wrong number (%d) of ZSKs in KSR",j);
    }
    /* Added for 1024->2048 ZSK fallback path KSRs so that a single ZSK at the begining or end is acceptable */
    if(i != j) k++;
    else if(i == 1) {
      if(strcmp(skrk[0]->PublicKey,ksrk[0]->PublicKey)) k++;
    } else if(i == 2) {
      if(
	 ((strcmp(skrk[0]->PublicKey,ksrk[0]->PublicKey)
	   || strcmp(skrk[1]->PublicKey,ksrk[1]->PublicKey))
	  &&
	  (strcmp(skrk[0]->PublicKey,ksrk[1]->PublicKey)
	   || strcmp(skrk[1]->PublicKey,ksrk[0]->PublicKey)))
	 ) k++;
    } else k++;
    if(k) logger_error("Last SKR and current KSR keys do not match");
    // nmatch: label no longer needed after 1024->2048 ZSK fallback changes above
    if(k) {
      logger_error("Problem with ZSK trust daisy chain.");
      ksrinvalid++;
    }
  }

  if(ksrinvalid) goto end;

  logger_info("...PASSED.");
  logger_info("");

  {
    mbuf *bp;
    bp = pgp_wordlist2(hash,hashlen);
    logger_info("SHA256 hash of KSR:");
    hdump(hash,hashlen);
    logger_info("%s%s%s", PGPWORDLIST_BEGIN, bp->p0, PGPWORDLIST_END);
    mbuf_free(bp);
  }

  printf("Is this correct (y/N)? ");
  if(fgets(lbuf,sizeof(lbuf),stdin) == NULL /* CVTY - tainted? */
     || (lbuf[0] != 'y' && lbuf[0] != 'Y')) {
    printf("\n");
    logger_warning("Aborting KSR signing...");
    goto end;
  }
  logger_info("");

  /*
   * Sign the KSR
   */
  snprintf(lbuf2,sizeof(lbuf2),"tmp/%s_%s_%u_tmp_skr.xml",progname,nowstr,getpid());
  if((ftmp=fopen(lbuf2,"w+")) == NULL) {
    logger_error("Cannot create output file %s",lbuf2);
    goto end;
  }
  signem(ftmp,xs);

  if(ksrinvalid) goto end;

  rewind(ftmp);

  if((fout=fopen(skrfile,"w")) == NULL) {
    logger_error("Cannot open output SKR file %s",skrfile);
    goto end;
  }
  /* replace current SKR file */
  snprintf(lbuf,sizeof(lbuf),"%s.%s",skrold,nowstr);
  rename(skrold,lbuf); /* move old one */

  while(fgets(lbuf,sizeof(lbuf),ftmp)) {
    fprintf(fout,"%s",lbuf);
  }
  rewind(ftmp);
  hashlen = hashfile(ftmp,HASH_SHA256,hash);
  fclose(fout);
  snprintf(lbuf,sizeof(lbuf),"mv %s %s",lbuf2,skrold);
  system(lbuf);
  /*rename(lbuf2,skrold); this doesnt work in the KC DVD/FD env */
  
  logger_info("Generated new SKR in %s",skrfile);

  /*
   * Display new SKR
   */
  for(i=0;i<xss->rqrscnt;i++) free_requestresponse(xss->rqrs[i]);
  memset(xss,0,sizeof(xmlstate));
  rewind(ftmp);
  xss->fin = ftmp;
  xmlparse("",xss);
  fclose(ftmp);

  if(xss->rqrscnt <= 0) {
    logger_error("No KSR responses found in SKR");
    goto end;
  }
  qsort((void *)xss->rqrs,xss->rqrscnt,sizeof(void *),expmaxcmpr);
  display_reqresp(xss->rqrs,xss->rqrscnt);

  logger_info("");

  {
    mbuf *bp;
    bp = pgp_wordlist2(hash,hashlen);
    logger_info("SHA256 hash of SKR:");
    hdump(hash,hashlen);
    logger_info("%s%s%s", PGPWORDLIST_BEGIN, bp->p0, PGPWORDLIST_END);
    mbuf_free(bp);
  }

  ret = 0;

 end:
  /* memset(0) set ->rqrscnt to zero */
  for(i=0;i<xss->rqrscnt;i++) free_requestresponse(xss->rqrs[i]);
  /* ditto */
  for(i=0;i<xs->rqrscnt;i++) free_requestresponse(xs->rqrs[i]);
  pkcs11_close(NULL);

  return ret;
}

/*
 *! Fill in DNSSEC specific info for a HSM key.
\param pk void casted pointer to pkcs11 control block
\return non-null populated krecord upon success, otherwise return NULL.
*/
static krecord *fillinkinfo(void *pk)
{
  char *p0;
  uint8_t *q,*q0,lbuf[4098];
  int elen,mlen,dlen;
  krecord *kr;
  size_t psize;

  if(pk == NULL) return NULL;
  if((kr=(krecord *)calloc(1,sizeof(krecord))) == NULL) return NULL;
  kr->pkcb = pk;
  kr->bits = pkcs11_bits(pk);
  /* in order to make the code easy to read - make copies in both pkcs11 and dnssec space - yech. */
  kr->modulus = mbuf_dup(pkcs11_modulus(pk));
  kr->pubexp = mbuf_dup(pkcs11_pubexp(pk));
  kr->label = mbuf_dup(pkcs11_label(pk));

  elen = (int)(kr->pubexp->pc - kr->pubexp->p0);
  if(elen > 255) {
    logger_error("Unsupported public exponent size %d",elen);
    free_keyrecord(kr);
    return NULL;
  }
  // Narrow range of acceptable KSK match policy exponent and size
  if(elen != KSK_RRSIG_RSA_EXPONENT_BNLEN
     || memcmp(kr->pubexp->p0,KSK_RRSIG_RSA_EXPONENT_BN,KSK_RRSIG_RSA_EXPONENT_BNLEN)) {
    logger_error("Unsupported public exponent");
    free_keyrecord(kr);
    return NULL;
  }  
  if(kr->bits != KSK_RRSIG_RSA_KEYSIZE) {
    logger_error("Unsupported key size %d",kr->bits);
    free_keyrecord(kr);
    return NULL;
  }
  mlen = (int)(kr->modulus->pc - kr->modulus->p0);
  
  q = q0 = (uint8_t *)malloc((elen+mlen+1));
  psize = ((4*( (elen+mlen+1) +1))/3) + 1;
  p0 = (char *)malloc(psize);
  *q++ = (uint8_t)elen;
  memcpy(q,kr->pubexp->p0,elen);
  q += elen;
  memcpy(q,kr->modulus->p0,mlen);
  q += mlen;
  
  dlen = (int)(q-q0);

  base64encode(p0,psize,q0,dlen);
  
  kr->PublicKey = p0;
  
  kr->Flags = (DNSKEY_ZONE_FLAG | DNSKEY_SEP_FLAG);
  kr->Protocol = 3;
  kr->Algorithm = KSK_RRSIG_ALG;
  
  /* compute tag */
  q = lbuf;
  *(uint16_t *)q = htons(kr->Flags);
  q += 2;
  *(uint8_t *)q = (uint8_t)kr->Protocol;
  q++;
  *(uint8_t *)q = (uint8_t)kr->Algorithm;
  q++;
  memcpy(q,q0,dlen);
  free(q0);
  q += dlen;
  kr->keyTag = dnssec_keytag(lbuf,(int)(q-lbuf));

  /* use pkcs11 CKA_LABEL since we will avoid creating duplicate labels */
  kr->keyIdentifier = strdup((char *)kr->label->p0);
    
  return kr;
}

/*! get all KSKs from the HSM via pkcs11 while interacting with the user and
    store locally.

    \param ksks storage array for pointers to KSK krecords
    \return number of KSKs found
*/
static int getKSKs(krecord *ksks[])
{
  void *pk[MAX_KSKS];
  int i,j,n,m,m1,m2;
  // Added support for being able to load specific keys - not all which can cause confusion
  // Was not a problem with one key in the HSM
  m1 = m2 = 0;
  if(ksklabel_1) m1 = strlen(ksklabel_1);
  if(ksklabel_2) m2 = strlen(ksklabel_2);
  n = pkcs11_getpub(NULL,NULL,NULL,NULL,pk,MAX_KSKS);
  for(i=0,j=0;i<n;i++) {
    if(m1) { // is it a key we want
      mbuf *bp;
      bp = mbuf_dup(pkcs11_label(pk[i]));
      m = (int)(bp->pc - bp->p0);
      if(m2) {
	if((m == m1 && memcmp(bp->p0,ksklabel_1,m) == 0)
	   || (m == m2 && memcmp(bp->p0,ksklabel_2,m) == 0) ) goto accept;
      } else if(m == m1 && memcmp(bp->p0,ksklabel_1,m) == 0) goto accept;
      mbuf_free(bp);
      continue;
    accept:
      mbuf_free(bp);
    }
    if((ksks[j] = fillinkinfo(pk[i])) == NULL) { // load keys. any failure is serious enough to terminate
      for(i=0;ksks[j] && i<n;i++) { // clean up after ourselves
	free_keyrecord(ksks[j]);
	ksks[j] = NULL;
      }
      return -1;
    }
    j++;
  }
  return j;
}

/******************************************************************
 * RRSIG function
 ******************************************************************/

#ifdef DO_LIVE_ASN1_CALCULATION
#include "rl_der.h"
#endif

/*! Compute padded hash for digital signatures.

    DNSSEC, CERTS, and S/MIME all use this same pkcs1 digital signature
    padding scheme. This meets FIPS 186-3.

    \param htype hash type to compute (sha1 sha256)
    \param hash buffer holding hash
    \param hashlen length of hash
    \param klen key length that will be used to sign.
    \return mbuf containing padded hash.  Null if failed.
 */
static mbuf *pkcs1padrsa(int htype,uint8_t *hash,int hashlen,int klen)
{
  uint8_t *q,*hdr;
  int i,n,hdrlen;
  mbuf *bp;

#ifdef DO_LIVE_ASN1_CALCULATION
  derb *db,_db;
  mbuf *bpA,*bpB;

  db = &_db;
  memset(db,0,sizeof(derb));
  bpA = start_sequence(db);
  switch(htype) {
  case HASH_SHA1:
    dgstalg(db3,"sha1",NULL,1); break;
  case HASH_SHA256: 
    dgstalg(db3,"sha256",NULL,1); break;
  default:
    logger_error("RSA PKCS Unsupported hash %d",htype);
    mbuf_free(bpA);
    return NULL;
  }
  octet(db3,hash,hashlen);
  end_sequence(db,bpA);
  bpB = mbuf_flat(bpA);
  hdrlen = (int)(bpB->pc - bpB->p0);
  hdr = bpB;

  bp = alloc_mbuf(klen);
  q = bp->p0;
  *q++ = 0x00;
  *q++ = 0x01; /* set private key bit */

  n = klen - (3+hdrlen);
  for(i=0;i<n;i++) *q++ = 0xFF;
  *q++ = 0x00;

  memcpy(q,hdr,hdrlen);
  q += hdrlen;
  mbuf_free(bpB);

  bp->pc += klen;
  return bp;
#else /* DO_LIVE_ASN1_CALCULATION */
  /*
   * format: 00 01 FF .... 00 HASH
   * 00 01 n-FF ... 00:  n = (modulus len/8 - 3 - 20|32)
   * SHA-1   30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 ..sha-1 hash
   * SHA-256 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
   * Why pull in all the ASN stuff for just a few bytes?
   * Use your friendly ASN/DER packedge to create new byte strings
   * as new algorithms get implemented.
   */
  uint8_t sha1hdr[]={0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
  uint8_t sha256hdr[]={0x30,0x31,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};

  switch(htype) {
  case HASH_SHA1:
    hdrlen = sizeof(sha1hdr);
    hdr = sha1hdr;
    break;
  case HASH_SHA256:
    hdrlen = sizeof(sha256hdr);
    hdr = sha256hdr;
    break;
  default:
    return NULL;
  }

  bp = alloc_mbuf(klen);
  q = bp->p0;
  *q++ = 0x00;
  *q++ = 0x01; /* set private key bit */

  n = klen - (hashlen+3+hdrlen);
  for(i=0;i<n;i++) *q++ = 0xFF;
  *q++ = 0x00;
  
  memcpy(q,hdr,hdrlen);
  q += hdrlen;

  memcpy(q,hash,hashlen);

  bp->pc += klen;
  return bp;
#endif /* DO_LIVE_ASN1_CALCULATION */
}

/*! Helper routine for qsort

    Used to canonicalize key order for rrsig().

    \param a first void casted krecord to compare
    \param b second void casted krecord to compare
    \return binary "lexographical" compare between key byte strings in the krecords
 */
static int rrcmpr(const void *a,const void *b)
{
  krecord * const *d1 = a;
  krecord * const *d2 = b;
  wirerr *r1,*r2;
  int n;
  r1 = (wirerr *)(*d1)->user;
  r2 = (wirerr *)(*d2)->user;
  n = min(r1->rdatalen,r2->rdatalen);
  return memcmp(r1->rdata,r2->rdata,n);
}

/*! compute the RRSIGs

    compute the RRSIGs based on keys[] using keys[] where the signer flag is
    set. RRSIG is calculated using domain dn, t_inception,time_t,
    t_expiration. If showkeys is initially set, routine will write keys to
    ftmp as well as sigs. Note: BIND validateable keybundles are written into
    "tmp" dir ("skr_keybundle_template") to simplify final testing.

    \param keys list of keys over which we want the RRSIG
    \param keycnt number of keys in list
    \param dn doman name to incorporate into calculation
    \param t_inception RRSIG inception time
    \param t_expiration RRSIG expiration time
    \param showkeys set on first call so that keys are output as well as signatures
    \param ftmp where output is written.
    \return 0 if success.
 */
int rrsig(krecord *keys[],int keycnt,char *dn,time_t t_inception,time_t t_expiration,int *showkeys,FILE *ftmp)
{
  uint8_t *w,wire[1024];
  int n,i,k,ret,ilabel;
  krecord *dr;
  uint8_t hash[1024];
  int hashlen;
  uint8_t *rdata;
  int rdatalen;
  uint16_t *rdlen;
  wirerr *rr;
  char inception[30],expiration[30];
  mbuf *bp;
  FILE *fkeyb;
  char lbuf[MAXPATHLEN];

  /* 
   * Create test keybundles in zonefile format so that bind tools can
   * be used to independently test signatures. 
   * To test RRSIG just created:
   *   dnssec-signzone -v 10 -o . skr.keybundle
   * Output should indicate our KSK RRSIGs were "retained"
   */
  sprintf(lbuf,skr_keybundle_template,testitbcnt++);
  if((fkeyb=fopen(lbuf,"w+"))) {
    fprintf(fkeyb,"; To test RRSIG s  we have created:\n;   dnssec-signzone -v 10 -o %s %s\n; Output should indicate our KSK RRSIGs were \"retained\"\n",dn,lbuf);
    fprintf(fkeyb,"%s 12345 IN SOA ns.iana.org. NSTLD.iana.org. 2009120102 1800 900 604800 86400\n",dn);
  }

  ret = 0;

  gmtstrtime(t_inception,inception);
  gmtstrtime(t_expiration,expiration);

  for(k=0;k<keycnt;k++) {
    dr = keys[k];

#ifdef RRSIG_WIRE_REUSE
    if(dr->user) continue; /* skip pre-calculated ones */
#else
    if(dr->user) {
      free(dr->user);
      dr->user = NULL;
    }
#endif

    /*
     * RR(i) = owner | type | class | TTL | RDATA length | RDATA
     * owner = canonical
     * type(16) A = 1, DNSKEY = 48 RRSIG = 46  all Network Order
     * class(16) IN = 1
     * ttl (32)
     * RDATA length(16)
     */
    w = wire;
    
    n = dnssec_dn2wire(dn,w); w += n;
    *(uint16_t *)w = htons(48); w += 2; /* type = 48 for DNSKEY */
    *(uint16_t *)w = htons(1); w += 2; /* class = 1 for IN */
    *(uint32_t *)w = htonl(DefaultTTL); w += 4; /* ttl */
    rdlen = (uint16_t *)w; w += 2; /* rdata length */

    rdata = w;
    { /* DNSKEY canonical order is RDATA: flags|proto|alg|key */
      *(uint16_t *)w = htons(dr->Flags); w += 2;
      *(uint8_t *)w = dr->Protocol; w++;
      *(uint8_t *)w = dr->Algorithm; w++;
      n = base64decode(dr->PublicKey,w,sizeof(wire)); w += n;
    }
    n = (int)(w - wire);
    rdatalen = (int)(w - rdata); 
    *rdlen = htons(rdatalen);

    rr = (wirerr *)malloc(sizeof(wirerr)+n);
    rr->len = n;
    rr->w = (uint8_t *)(rr+1);
    memcpy(rr->w,wire,n);
    rr->rdata = rr->w + (n - rdatalen);
    rr->rdatalen = rdatalen;
    dr->user = (void *)rr;
  }

  /* keys must be in canonical order - sort */
  qsort((void *)keys,keycnt,sizeof(void *),rrcmpr);

  for(k=0;k<keycnt;k++) {
    dr = keys[k];
    if(fkeyb) fprintf(fkeyb,"%s %u IN DNSKEY %d 3 %d %s\n",dn,DefaultTTL,dr->Flags,dr->Algorithm,dr->PublicKey);

    if( *showkeys ) {
      fprintf(ftmp,"<Key keyIdentifier=\"%s\" keyTag=\"%05u\">\n",dr->keyIdentifier,dr->keyTag);
      fprintf(ftmp,"<TTL>%u</TTL>\n",DefaultTTL);
      fprintf(ftmp,"<Flags>%d</Flags>\n",dr->Flags);
      fprintf(ftmp,"<Protocol>%d</Protocol>\n",dr->Protocol);
      fprintf(ftmp,"<Algorithm>%d</Algorithm>\n",dr->Algorithm);
      fprintf(ftmp,"<PublicKey>%s</PublicKey>\n",dr->PublicKey);
      fprintf(ftmp,"</Key>\n");
    }
  }
  *showkeys = 0; /* show keys only once if multiple calls */

  ilabel = dndepth(dn);

  for(k=0;k<keycnt;k++) {
    genhashctx gh;

    if(keys[k]->signer == 0) continue;

    dr = keys[k];

    if((gh.type=algtohash(dr->Algorithm)) < 0) {
      logger_error("%s: Currently algorithm %d is not supported",__func__,dr->Algorithm);
      ret--;
      continue;
    }

    hashit(&gh,NULL,0);
    w = wire;
    *(uint16_t *)w = htons(48); w += 2; /* type 48 = DNSKEY */
    *(uint8_t *)w = dr->Algorithm; w += 1;
    *(uint8_t *)w = ilabel; w += 1;  /* label = 1 */
    *(uint32_t *)w = htonl(DefaultTTL); w += 4;
    *(uint32_t *)w = htonl(t_expiration); w += 4;
    *(uint32_t *)w = htonl(t_inception); w += 4;
    *(uint16_t *)w = htons(dr->keyTag); w += 2;
    n = dnssec_dn2wire(dn,w); w += n; /* dn0 */
    n = (int)(w-wire);

    hashit(&gh,wire,n);

    for(i=0;i<keycnt;i++) {
      rr = (wirerr *)keys[i]->user;
      hashit(&gh,rr->w,rr->len);
    }

    hashlen = hashit(&gh,hash,0);

    if(fkeyb) fprintf(fkeyb,"%s %u IN RRSIG DNSKEY %d %d %u %s %s %d %s ",dn,DefaultTTL,dr->Algorithm,ilabel,DefaultTTL,expiration,inception,dr->keyTag,dn);
    fprintf(ftmp,"<Signature keyIdentifier=\"%s\">\n",dr->keyIdentifier);
    fprintf(ftmp,"<TTL>%u</TTL>\n",DefaultTTL);
    fprintf(ftmp,"<TypeCovered>DNSKEY</TypeCovered>\n");
    fprintf(ftmp,"<Algorithm>%d</Algorithm>\n",dr->Algorithm);
    fprintf(ftmp,"<Labels>%d</Labels>\n",ilabel);
    fprintf(ftmp,"<OriginalTTL>%u</OriginalTTL>\n",DefaultTTL);
    {
      char tbuf[30];

      sec2ztime(t_expiration,tbuf);
      fprintf(ftmp,"<SignatureExpiration>%s</SignatureExpiration>\n",tbuf);
      sec2ztime(t_inception,tbuf);
      fprintf(ftmp,"<SignatureInception>%s</SignatureInception>\n",tbuf);
    }
    fprintf(ftmp,"<KeyTag>%05u</KeyTag>\n",dr->keyTag);
    fprintf(ftmp,"<SignersName>%s</SignersName>\n",dn);
    fprintf(ftmp,"<SignatureData>");
    
    n = sizeof(wire);

    bp = pkcs1padrsa(gh.type,hash,hashlen,dr->bits/8);
    if(dr->pkcb) {
      if(pkcs11_rsasignit2(dr->pkcb,bp->p0,(int)(bp->pc - bp->p0),wire,&n)) {
        logger_error("%s: Could not sign RRset",__func__);
        ret--;
      } else {
        char out[1024];
        base64encode(out,sizeof(out),wire,n);
        if(fkeyb) fprintf(fkeyb,"%s\n",out);
        fprintf(ftmp,"%s",out);
      }
    } else {
      if(fkeyb) fprintf(fkeyb,"NOHSM\n");
      fprintf(ftmp,"NOHSM");
    }
    mbuf_free(bp);
    fprintf(ftmp,"</SignatureData>\n");
    fprintf(ftmp,"</Signature>\n");
  }
  if(fkeyb) {
    fprintf(fkeyb,"\n");
    fclose(fkeyb);
  }

  return ret;
}


/*! validate the keybundle

    validate the keybundle made up of keys in klist and signatures in s.
    returns 0 if validation successful. HSM path has no reliance on external
    routines like OPENSSL. If no HSM, OPENSSL is used. This is true for the
    Web based pre-acceptance testing on KSRs

    verifies proof of possesion of a private key creating signature "s"
    corresponding to one of the keys in "klist". Basically create RRSIG for
    klist and compare. Note this is used for KSK and ZSK signatures. For KSK
    the private key MUST be in the HSM - an important link in the chain of
    KSR/SKRs and therefore trust. For ZSK it does not as it is only proof of
    possesion for the KSR provider.

    \param s Signature created by one of the key in klist
    \param klist List of krecord structures.
    \return 0
 */
int validatekeybundle(signature *s,krecord *klist)
{
  krecord *sk,*keys[MAX_KEYS];
  int keycnt;

  uint8_t hash[256];  /* 20 bytes for sha1, 32 for sha256 */
  int hashlen;
  int htype;

  int ret;

  ret = -1;

  for(sk=klist;sk;sk=sk->next) {
    if(s->SignatureData && sk->PublicKey
       && strcmp(s->keyIdentifier,sk->keyIdentifier) == 0
       ) break;
  }
  if(sk == NULL) {
    logger_error("%s: No key in bundle matching signature %s",__func__, s->keyIdentifier);
    return -1;
  }

  {
    uint8_t wire[1024],*w;
    int n;
    uint16_t *rdlen;
    uint8_t *rdata;
    int rdatalen;
    wirerr *rr;
    krecord *dr;

    keycnt = 0;
    for(dr=klist;dr;dr=dr->next) {

#ifdef RRSIG_WIRE_REUSE
      if(dr->user) {
        keys[keycnt++]  = dr;
        continue;
      }
#else
      if(dr->user) {
        free(dr->user);
        dr->user = NULL;
      }
#endif

      /*
       *! RR(i) = owner | type | class | TTL | RDATA length | RDATA
       *! owner = canonical
       *! type(16) A = 1, DNSKEY = 48 RRSIG = 46  all Network Order
       *! class(16) IN = 1
       *! ttl (32)
       *! RDATA length(16)
       */
      w = wire;
      
      n = dnssec_dn2wire(s->SignersName,w); w += n;
      *(uint16_t *)w = htons(48); w += 2; /* type = 48 for DNSKEY */
      *(uint16_t *)w = htons(1); w += 2; /* class = 1 for IN */
      *(uint32_t *)w = htonl(dr->TTL); w += 4; /* ttl */
      rdlen = (uint16_t *)w; w += 2; /* rdata length */
      
      rdata = w;
      { /* for DNSKEY */
        /* canonical order is RDATA: flags|proto|alg|key */
        *(uint16_t *)w = htons(dr->Flags); w += 2;
        *(uint8_t *)w = dr->Protocol; w++;
        *(uint8_t *)w = dr->Algorithm; w++;
        n = base64decode(dr->PublicKey,w,sizeof(wire)); w += n;
      }
      n = (int)(w - wire);
      rdatalen = (int)(w - rdata); 
      *rdlen = htons(rdatalen);
      
      rr = (wirerr *)malloc(sizeof(wirerr)+n);
      rr->len = n;
      rr->w = (uint8_t *)(rr+1);
      memcpy(rr->w,wire,n);
      rr->rdata = rr->w + (n - rdatalen);
      rr->rdatalen = rdatalen;
      dr->user = (void *)rr;

      keys[keycnt++]  = dr;
    }
    /* keys must be in canonical order */
    qsort((void *)keys,keycnt,sizeof(void *),rrcmpr);
  }

  {
    uint8_t wire[1024],*w;
    int n;
    genhashctx gh;

    if((htype=algtohash(s->Algorithm)) < 0) {
      logger_error("%s Currently algorithm %d is not supported",__func__,s->Algorithm);
      return -1;
    }
    gh.type = htype;
    hashit(&gh,NULL,0);
    w = wire;
    *(uint16_t *)w = htons(48); w += 2; /* type = DNSKEY */
    *(uint8_t *)w = s->Algorithm; w += 1;
    *(uint8_t *)w = s->Labels; w += 1;  /* label = 1 */
    *(uint32_t *)w = htonl(s->OriginalTTL); w += 4;
    *(uint32_t *)w = htonl(s->SignatureExpiration); w += 4;
    *(uint32_t *)w = htonl(s->SignatureInception); w += 4;
    *(uint16_t *)w = htons(s->KeyTag); w += 2; /* here w/ KSK flag */
    n = dnssec_dn2wire(s->SignersName,w); w += n; /* dn0 */
    n = (int)(w-wire);

    hashit(&gh,wire,n);

    for(n=0;n<keycnt;n++) {
      wirerr *rr;
      rr = (wirerr *)keys[n]->user;
      hashit(&gh,rr->w,rr->len);
    }
    hashlen = hashit(&gh,hash,0);
  }

  {
    int i;
    krecord *kr;
    uint8_t usig[1024];
    int usiglen,klen;
    mbuf *bp;

    klen = sk->bits/8;
    usiglen = base64decode(s->SignatureData,usig,sizeof(usig));
    bp = pkcs1padrsa(htype,hash,hashlen,klen);

    /* find matching KSK key */
    for(i=0;i<nksk;i++) {
      if(strcmp(ksks[i]->PublicKey,sk->PublicKey) == 0) {
        kr = ksks[i];
        break;
      }
    }
    if(i < nksk) { /* Found it - use private key in HSM */
      uint8_t wire[1024];
      int n;

      if(debug) logger_debug("in HSM %05u",kr->keyTag);

      n = sizeof(wire);
      if(pkcs11_rsasignit2(kr->pkcb,bp->p0,(int)(bp->pc - bp->p0),wire,&n)) {
        logger_error("%s: Could not sign data",__func__);
      } else {
        if(usiglen == n || memcmp(usig,wire,n) == 0) ret = 0;
      }
    } else if((sk->Flags & DNSKEY_SEP_FLAG) == 0) { /* ok to not have priv key for ZSK */
      ret = pkcs11_hsmverify(sk->modulus,sk->pubexp,usig,usiglen,bp->p0,(int)(bp->pc - bp->p0));
    } else { /* but MUST have private key for KSK */
      logger_error("%s: MUST vaidate with private KSK",__func__);
    }
    mbuf_free(bp);
  }

  if(ret) {
    logger_error("Cannot validate private key ownership for keyIdentifier |%s|",
      sk->keyIdentifier);
#ifdef KEEPTRY /* define for testing to keep checking other key bundles after an error */
    ret = 0;
#else
    ksrinvalid++;
#endif
  }
  return ret;
}
