/*
 * $Id: kskgen.c 567 2010-10-28 05:11:10Z jakob $
 *
 * Copyright (c) 2009 Internet Corporation for Assigned Names ("ICANN")
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
#include "kskgen.h"
#include "kskparams.h"
#include "rlder.h"
#include "dnssec.h"
#include "pkcs11_dnssec.h"
#include "compat.h"

#define LOGDIR "."  /*!< Directory for logfiles */

static const char *progname = "kskgen";

static mbuf *create_csr(kcrecord *dc);
static kcrecord *fillinkinfo(void *pk);
static int setkeyalg(kcrecord *dc,int alg);
static mbuf *pkcs1padrsasign(int htype,uint8_t *hash,int hashlen,kcrecord *dc);

/***************************************************************
 *! Generates a KSK and associated publication material
 *!
 *! Usage: kskgen<CR> Generates a new KSK in the HSM and files below.
 *!        kskgen ksk-label<CR> Creates the files below from the KSK 
 *!        CKA_LABEL'd ksk-label.
 *!
 *! output: K12345.csr in binary DER
 *! where: 
 *!  "12345" is the a random unique label of the newly generated key
 *!  K12345.csr is a simple CSR (no attributes or extensions)
 *!
 *! To test:
 *!  openssl req -inform der -in K12345.csr -noout -text -verify
 *!
\param argv[1] if specified, it is the pkcs11 CKA_LABEL for the HSM key to generate the CSR from.  If not specified, a new key is generated and used to create the CSR.
\return 0 on success; -1 on error.
 ***************************************************************/
int main(int argc,char *argv[])
{
  char *dn_cn,*dn_misc,lbuf[MAXPATHLEN];
  FILE *fp;
  kcrecord *dc;
  derb _db,*db;
  int hashlen;
  uint8_t hash[512];
  mbuf *bp;
  char ztimestamp[512];
  char *ksklabel = NULL;

  int original_argc = argc;
  char **original_argv = argv;

  {
    int ch;
    extern char *optarg;
    extern int optind;
    extern int optopt;
    extern int opterr;
    
    while((ch=getopt(argc,argv,"Vh")) != -1) {
      switch(ch) {
      case 'V':
      printf("%s %s version %s\n", PACKAGE_TARNAME, progname, PACKAGE_VERSION);
        exit(0);
      case 'h':
      default:
        printf("Usage: %s [CKA_LABEL of existing key]\n", argv[0]);
        printf("  - with no arguments will generate a new KSK with unique\n");
        printf("    CKA_LABEL in the specified HSM slot\n");
        printf("  - with one argument will use that KSK.\n");
        printf("Output will be a CSR in file [CKA_LABEL].csr\n");
        exit(-1);
      }
    }
    argc -= optind;
    argv += optind;
  }

  /* first remaining argument is CKA_LABEL */
  if (argc) {
    ksklabel = argv[0];
  }
  
  /* Init log system and say hello */
  logger_init(progname, LOGDIR, LOG_STDOUT);
  logger_hello(original_argc, original_argv);

  /*
   * Activate HSM
   */
  if(pkcs11_init(PKCS11_HSMCONFIGDIR)) return -1;

  if(ksklabel) { /* use existing one */
    void *dcs[2];

    logger_info("Looking for RSA keypair labeled \"%s\"...",ksklabel);

    if(pkcs11_getpub(ksklabel,NULL,NULL,NULL,dcs,1) != 1) {
      logger_error("Could not find an existing key labeled \"%s\"",ksklabel);
      return -1;
    }

    if((dc=fillinkinfo(dcs[0])) == NULL) {
      logger_error("Could not fill in DNSSEC+X509 key info");
      return -1;
    }

    logger_info("Found keypair labeled \"%s\"",dc->label->p0);

  } else { /* generate the next KSK */
    void *dcs;

    logger_info("Generating %d bit RSA keypair...",DNSSEC_KSK_RSA_BITS);

    if((dcs=pkcs11_genrsakey(DNSSEC_KSK_RSA_BITS,DNSSEC_KSK_FLAGS)) == NULL) {
      logger_error("Key generaton failed");
      return -1;
    }

    if((dc=fillinkinfo(dcs)) == NULL) {
      logger_error("Could not fill in DNSSEC+X509 key info");
      return -1;
    }

    logger_info("Created keypair labeled \"%s\"",dc->label->p0);
    logger_info("");
    ksklabel = (char *)dc->label->p0;
  } 

  logger_info("SHA256 DS resource record and hash:");
  logger_info("%s IN DS %u %u 2 %s",dc->dn,dc->tag,dc->alg,dc->ds2);

  {
    mbuf *bp;

    bp = pgp_wordlist2(dc->ds2bp->p0,(int)(dc->ds2bp->pc - dc->ds2bp->p0));
    logger_info("%s%s%s", PGPWORDLIST_BEGIN, bp->p0, PGPWORDLIST_END);
    mbuf_free(bp);
  }
  logger_info("");

  /* distinguished name */
  db = &_db;
  memset(db,0,sizeof(derb));
  bp = rlder_start_sequence(db);
  /* O and OU */
  rlder_pname(db,"organizationName",DN_O);
  rlder_pname(db,"organizationalUnitName",DN_OU);
  /* commonName: text + current time */
  sec2ztime(time(NULL), ztimestamp);
  /* FIXME: timestamp should be set to the time when the key was generated,
            not when the CSR was generated. Not sure how to fix this */
  snprintf(lbuf,sizeof(lbuf),"Root Zone KSK %s", ztimestamp);
  dn_cn = strdup(lbuf);
  rlder_pname(db,"commonName",dn_cn);
  /* resourceRecord: DS resource record */
  snprintf(lbuf,sizeof(lbuf),"%s IN DS %u %u %u %s",dc->dn,dc->tag,dc->alg,DS_SHA256,dc->ds2);
  dn_misc = strdup(lbuf);
  rlder_pname(db,OID_DNS,dn_misc);
  rlder_end_sequence(db,bp);
  dc->distinguishedname = mbuf_flat(bp);
  /* FIXME: do not include email address at all (the specification,
     draft-icann-dnssec-trust-anchor, says we should not include) */
  dc->email = DN_EMAIL;

  /* 
   * create a CSR - a simple private key proof of possesion
   */
  if((bp = mbuf_flat(create_csr(dc))) == NULL) return -1;
  snprintf(lbuf,sizeof(lbuf),"%s.csr",ksklabel);
  if((fp=fopen(lbuf,"w+")) == NULL) {
    logger_error("Can't open \"%s\"",lbuf);
    return -1;
  }
  mbuf_out(bp,fp);

  logger_info("Created CSR file \"%s.csr\":",ksklabel);
  logger_info("O: %s",DN_O);
  logger_info("OU: %s",DN_OU);
  logger_info("CN: %s",dn_cn);
  logger_info("%s: %s",OID_DNS,dn_misc);
  logger_info("");
  free(dn_cn);
  free(dn_misc);

  rewind(fp);
  hashlen = hashfile(fp,HASH_SHA256,hash);
  fclose(fp);
  {
    mbuf *bp;
    bp = pgp_wordlist2(hash,hashlen);
    logger_info("%s.csr SHA256 thumbprint and hash:",ksklabel);
    hdump(hash,hashlen);
    logger_info("%s%s%s", PGPWORDLIST_BEGIN, bp->p0, PGPWORDLIST_END);
    mbuf_free(bp);
  }
  logger_info("");

  pkcs11_close(NULL);

  return 0;
}

/*
 *! return an mbuf containing a der representation of a CSR formed from dc 
\param dc pointer to key structure to use for CSR, including pkcs11/HSM info
\return NULL if failed; ptr to mbuf containing CSR otherwise
 */
static mbuf *create_csr(kcrecord *dc)
{
  mbuf *bp,*bp0,*bp1,*bp2;
  derb db1,*db;
  genhashctx gh;
  uint8_t hash[512];
  int hashlen;

  db = &db1;
  memset(db,0,sizeof(derb));

  bp0 = rlder_start_sequence(db);

  /* CertificationRequestInfo */
  bp1 = rlder_start_sequence(db);

  /* version */
  rlder_integer(db,0);

  /* DN */
  bp = mbuf_dup(dc->distinguishedname);
  db->bpN->next = bp;
  db->bpN = bp;

  /* pub key */
  bp2 = rlder_start_sequence(db);
  rlder_dgstalg(db,"rsaEncryption",NULL,1);
  rlder_bitstring(db,dc->pkcspub->p0,(int)(dc->pkcspub->pc - dc->pkcspub->p0));
  rlder_end_sequence(db,bp2);

  /* extensions */
  bp2 = rlder_start_content(db,0);
  rlder_end_content(db,bp2);

  /* end CertificationRequestInfo */
  rlder_end_sequence(db,bp1);
  /* compute hash of CertificationRequestInfo */
  gh.type = dc->htype;
  hashit(&gh,NULL,0);
  for(bp=bp1;bp;bp=bp->next) hashit(&gh,bp->p0,(int)(bp->pc - bp->p0));
  hashlen = hashit(&gh,hash,0);

  /* add the digital signature */
  rlder_dgstalg(db,dc->dgstalg,NULL,1);
  if((bp = pkcs1padrsasign(gh.type,hash,hashlen,dc)) == NULL) return NULL;
  rlder_bitstring(db,bp->p0,(int)(bp->pc - bp->p0));
  mbuf_free(bp);

  rlder_end_sequence(db,bp0);

  return bp0;
}

/*******************************************************************
 *! Misc support
 *******************************************************************/

/*
 *! DNSSEC, CERTS, and S/MIME all use this same pkcs1 
 *! digital signature scheme. This meets FIPS 186-3
\param htype  Hash type e.g., HASH_SHA1 or HASH_SHA256
\param hash   ptr to buffer containing hash
\param hashlen  length of above hash in bytes
\param dc ptr to key record used to digitally sign the hash
\return NULL if error; ptr to allocated mbuf containing signed hash if ok
 */
static mbuf *pkcs1padrsasign(int htype,uint8_t *hash,int hashlen,kcrecord *dc)
{
  derb *db,_db;
  mbuf *bp,*bp1;

  /* create pkcs#1 structure for signing */
  db = &_db;
  memset(db,0,sizeof(derb));
  bp = rlder_start_sequence(db);
  switch(htype) {
  case HASH_SHA1:
    rlder_dgstalg(db,"sha1",NULL,1);  /* Adobe uses 0=no NULL */
    break;
  case HASH_SHA256:
    rlder_dgstalg(db,"sha256",NULL,1);  /* Adobe uses 0=no NULL */
    break;
  }
  rlder_octet(db,hash,hashlen);
  rlder_end_sequence(db,bp);

  bp1 = mbuf_flat(bp);
  bp = pkcs11_pkcssign(bp1,dc->pkcb);
  mbuf_free(bp1);

  return bp;
}
/* 
 *! shortcut to setting X.509 parameters 
\param dc ptr to key record to fill in with x509 hash/alg info
\param alg dnssec algortihm type
\return
 */
static int setkeyalg(kcrecord *dc,int alg)
{
  switch(alg) {
  case RRSIG_RSASHA1:
  case RRSIG_RSANSEC3SHA1:
    dc->htype = HASH_SHA1;
    dc->dgstalg = "sha1WithRSAEncryption";
    dc->dgstalg2 = "sha1";
    break;
  case RRSIG_RSASHA256:
    dc->htype = HASH_SHA256;
    dc->dgstalg = "sha256WithRSAEncryption";
    dc->dgstalg2 = "sha256";
    break;
  default:
    logger_error("%s: Unsupported algorithm number %d",__func__,alg);
    return -1;
  }
  return 0;
}

/* 
 *! just for fillinkinfo below 
\param dc ptr to key record to free
 */
static void kcrecord_free(kcrecord *dc)
{
  if(dc->ds2bp) mbuf_free(dc->ds2bp);
  if(dc->pkcspub) mbuf_free(dc->pkcspub);
  if(dc->distinguishedname) mbuf_free(dc->distinguishedname);
  if(dc->label) mbuf_free(dc->label);
  free(dc);
}

/* 
 *! called to fill in dnssec info - was important for keytag to be used for CKA_LABEL but team agreed to never do this in light of AEP Keyper implementation.  So now is called post PKCS11 keygen. Could use callbacks but keep it simple. 
\param pk void ptr to PKCS11 structure for an HSM key.
\return NULL if failed; otherwise newlly crated key record associated with pk.
*/
static kcrecord *fillinkinfo(void *pk)
{
  derb *db,_db;
  mbuf *bp,*modulus,*pubexp;
  kcrecord *dc;
  int bits;

  if(pk == NULL) {
    logger_error("No HSM was available");
    return NULL;
  }
  if((dc=(kcrecord *)calloc(1,sizeof(kcrecord))) == NULL) {
    logger_error("Could not allocate memory for key structure");
    exit(1);
  }
  dc->pkcb = pk;
  bits = pkcs11_bits(pk);
  modulus = pkcs11_modulus(pk);
  pubexp = pkcs11_pubexp(pk);
  dc->label = pkcs11_label(pk);

  if(setkeyalg(dc,DNSSEC_ALG)) {
    kcrecord_free(dc);
    return NULL;
  }
  strlcpy(dc->dn,DNSSEC_ROOT_DN,sizeof(dc->dn));
  dc->alg = DNSSEC_ALG;
  dc->proto = DNSSEC_PROTO;

  dc->flags = DNSSEC_KSK_FLAGS;

  if(bits != DNSSEC_KSK_RSA_BITS) {
    logger_error("%s: Requested and actual (%d bits) key lengths do not match.",__func__,bits);
  }

  /* pkcs pubkey format: modulus | exponent */
  db = &_db;
  memset(db,0,sizeof(derb));
  bp = rlder_start_sequence(db);
  rlder_binteger(db,modulus->p0,(int)(modulus->pc - modulus->p0));
  rlder_binteger(db,pubexp->p0,(int)(pubexp->pc - pubexp->p0));
  rlder_end_sequence(db,bp);
  if(dc->pkcspub) free(dc->pkcspub);
  dc->pkcspub = mbuf_flat(bp);

  /* dnssec dnskey format: exponent | modulus */
  {
    int i,cX;
    uint8_t *p,*pds,*ptag,*pdnskey,pbuf[4098];
    genhashctx gh;
    int hashlen;
    uint8_t hash[512];

    p = pds = pbuf;
    /* setup computation for DS rcords */
    p += dnssec_dn2wire(dc->dn,pds);
    /* compute tag and create dnskey */
    ptag = p;
    *(uint16_t *)p = htons(dc->flags);
    p += 2;
    *(uint8_t *)p = (uint8_t)dc->proto;
    p++;
    *(uint8_t *)p = (uint8_t)dc->alg;
    p++;
    pdnskey = p;
    i = (int)(pubexp->pc - pubexp->p0);
    if(i > 255) {
      logger_error("%s: encoding public keylen %d",__func__,i);
    }
    *p++ = (uint8_t)i;
    memcpy(p,pubexp->p0,i);
    p += i;
    i = (int)(modulus->pc - modulus->p0);
    memcpy(p,modulus->p0,i);
    p += i;
    base64encode(dc->dnskey,sizeof(dc->dnskey),pdnskey,(int)(p-pdnskey));
    dc->tag = dnssec_keytag(ptag,(int)(p-ptag));

    gh.type = HASH_SHA1;
    hashit(&gh,NULL,0);
    hashit(&gh,pds,(int)(p-pds));
    hashlen = hashit(&gh,hash,0);
    if((uint)(2*hashlen) >= sizeof(dc->ds1)) {
      logger_error("binary DS (%d) too long for string.",hashlen);
      kcrecord_free(dc);
      return NULL;
    }

    dc->ds1[0] = '\0';
    cX = sizeof(dc->ds1); /* CVTY fix */
    for(i=0;i<hashlen;i++) cX -= snprintf(&dc->ds1[2*i],cX,"%02X",hash[i]);

    gh.type = HASH_SHA256;
    hashit(&gh,NULL,0);
    hashit(&gh,pds,(int)(p-pds));
    hashlen = hashit(&gh,hash,0);
    if((uint)(2*hashlen) >= sizeof(dc->ds1)) {
      logger_error("binary DS (%d) too long for string.",hashlen);
      kcrecord_free(dc);
      return NULL;
    }

    if(dc->ds2bp) free(dc->ds2bp);
    dc->ds2bp = buf2mbuf(hash,hashlen);

    dc->ds2[0] = '\0';
    cX = sizeof(dc->ds2);
    for(i=0;i<hashlen;i++) cX -= snprintf(&dc->ds2[2*i],cX,"%02X",hash[i]);
  }

  return dc;
}
