/*
 * $Id: ksrcommon.c 583 2011-09-14 22:15:49Z lamb $
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

#include "util.h"
#include "logger.h"
#include "ksrcommon.h"
#include "ksrpolicy.h"
#include "pkcs11_dnssec.h"
#include "compat.h"

static signature *sig;
static signer *sgr;
static krecord *key;
static reqresp *rq;
static responsepolicy *rppolicy;
#if 0
static void dump_requestresponse(reqresp *rq);
#endif /* 0 */
static void free_signature(signature *s);
static void free_signer(signer *s);
static void free_responsepolicy(responsepolicy *r);
static char *gattr(char *tp,char *str);
static time_t ztime2sec(char *s);
static int fillinpinfo(krecord *kr);
static uint16_t updatekeytag(krecord *kr); // Called earlier to check RequestBundle keyTags with Key material

#define DBUFSIZE 2048

/*! Local zeroed memory allocation wrapper.

    No real recovery from lack of memory.  Better to just exit.

    \param n elements
    \param j  of size j bytes each
    \return char ptr to cleared allocated buffer
 */
static char *ksr_calloc(int n,int j)
{
  char *p;

  if((p=calloc(n,j)) == NULL) {
    logger_fatal("fatal: Can not calloc(%d,%d) memory in %s",n,j,__func__);
  }
  return p;
}

/*! Standalone lightweight basic recursive XML parser for KSR and SKR

    \param tp tag string to operate on.   Initially empty str "".
    \param xs I/O structure that also contains open imput file ptr "fin" 
    \return 0 on success. -1 for error
 */
int xmlparse(char *tp,xmlstate *xs)
{
  int i,k,sttg,otag;
  char lbuf[DBUFSIZE];
  char data[DBUFSIZE];
  char *q2p;

  data[0] = '\0';
  xs->depth++;
  sttg = 0;
  k = 0;
  otag = 0;

  if(xs->shorttag) {
    char *p,*q;
    q = &lbuf[2];
    p = tp;
    while(1) {
      if(*p == '\0' || *p == ' ') break;
      *q++ = *p++;
    }
    *q = '\0';
    xs->shorttag = 0;
    goto xmlprocess;
  }

  while((i=fgetc(xs->fin)) != EOF) {

    if(i == '\n' || i == '\r') i = ' '; /* continue; */

    if(k < (DBUFSIZE-3)) lbuf[k++] = i;
    else {
      lbuf[k] = i;
      logger_error("%s depth=%d buffer length exceeded - truncating",
        __func__,xs->depth);
      return -1;
    }

    if(i == '>' && sttg) {
      lbuf[k-1] = '\0';
      /*myx_syslog(LOG_INFO,"===============|%s|\n",lbuf);*/

      if(k > 1 && lbuf[k-2] == '/') {
        lbuf[k-2] = '\0';
        xs->shorttag = 1;
      }

      k = 0;
      sttg = 0;
      if(lbuf[1] != '/' && otag == 0) { /* started tag - resurse */
        char *p;
        /*
         * parse tag attributes at start
         */
        p = &lbuf[1];

#define KSR_STR "KSR "
        if(strncasecmp(p,KSR_STR,sizeof(KSR_STR)-1) == 0) {
          if((xs->ksrserial=gattr(p,"serial=")) == NULL) {
            logger_error("XML tag <%s> is missing attribute value for %s",p,"serial=");
            ksrinvalid++;
            break;
          }
          if((xs->ksrid=gattr(p,"id=")) == NULL) {
            logger_error("XML tag <%s> is missing attribute value for %s",p,"id=");
            ksrinvalid++;
            break;
          }
          if((xs->ksrdomain=gattr(p,"domain=")) == NULL) {
            logger_error("XML tag <%s> is missing attribute value for %s",p,"domain=");
            ksrinvalid++;
            break;
          }
          if(debug) logger_debug("=== KSR start serial=\"%s\" id=\"%s\" domain=\"%s\"",
            xs->ksrserial,xs->ksrid,xs->ksrdomain);

#define RQSTBNDLE_STR "RequestBundle "
        } else if(strncasecmp(p,RQSTBNDLE_STR,sizeof(RQSTBNDLE_STR)-1) == 0) {
          if(rq) {
            logger_warning("Unfreed RequestBundle");
            free_requestresponse(rq);
            rq = NULL;
          }
          rq = (reqresp *)ksr_calloc(1,sizeof(reqresp));
          if((rq->id=gattr(p,"id=")) == NULL) {
            logger_error("XML tag <%s> is missing attribute value for %s",p,"id=");
            ksrinvalid++;
            break;
          }
#define SGNR_STR "Signer "
        } else if(strncasecmp(p,SGNR_STR,sizeof(SGNR_STR)-1) == 0) {
          if(sgr) {
            logger_warning("Unfreed Signer");
            free_signer(sgr);
            sgr = NULL;
          }
          sgr = (signer *)ksr_calloc(1,sizeof(signer));
          if((sgr->keyIdentifier=gattr(p,"keyIdentifier=")) == NULL) {
            logger_error("XML tag <%s> is missing attribute value for %s",
              p,"keyIdentifier=");
            ksrinvalid++;
            break;
          }
#define KEY_STR "Key " 
        } else if(strncasecmp(p,KEY_STR,sizeof(KEY_STR)-1) == 0) {
          char *q2;
          if(key) {
            logger_warning("Unfreed Key");
            free_keyrecord(key);
            key = NULL;
          }
          key = (krecord *)ksr_calloc(1,sizeof(krecord));
          if((key->keyIdentifier=gattr(p,"keyIdentifier=")) == NULL) {
            logger_error("XML tag <%s> is missing attribute value for %s",
              p,"keyIdentifier=");
            ksrinvalid++;
            break;
          }
          if((q2=gattr(p,"keyTag=")) == NULL) {
            logger_error("XML tag <%s> is missing attribute value for %s",
              p,"keyTag=");
            ksrinvalid++;
            break;
          }
	  key->keyTag = strtol(q2,&q2p,10);
	  if(*q2p) {
	    logger_error("keyTag non numeric \"%s\"",q2);
            ksrinvalid++;
	    free(q2);
            break;
	  }
	  free(q2);
#define SIGNATURE_STR "Signature "
        } else if(strncasecmp(p,SIGNATURE_STR,sizeof(SIGNATURE_STR)-1) == 0) {
          if(sig) {
            logger_warning("Unfreed Signature");
            free_signature(sig);
            sig = NULL;
          }
          sig = (signature *)ksr_calloc(1,sizeof(signature));
          if((sig->keyIdentifier=gattr(p,"keyIdentifier=")) == NULL) {
            logger_error("XML tag <%s> is missing attribute value for %s",
              p,"keyIdentifier=");
            ksrinvalid++;
            break;
          }
#define RSPNSBNDLE_STR "ResponseBundle "
        } else if(strncasecmp(p,RSPNSBNDLE_STR,sizeof(RSPNSBNDLE_STR)-1) == 0) {
          if(rq) {
           logger_warning("Unfreed ResponseBundle");
            free_requestresponse(rq);
            rq = NULL;
          }
          rq = (reqresp *)ksr_calloc(1,sizeof(reqresp));
          rq->response = 1;
          if((rq->id=gattr(p,"id=")) == NULL) {
            logger_error("XML tag <%s> is missing attribute value for %s",p,"id=");
            ksrinvalid++;
            break;
          }
#define RQSTPLCY_STR "RequestPolicy"
        } else if(strncasecmp(p,RQSTPLCY_STR,sizeof(RQSTPLCY_STR)-1) == 0) {
          if(rppolicy) {
            logger_warning("Unfreed ResponsePolicy");
            free_responsepolicy(rppolicy);
            rppolicy = NULL;
          }
          rppolicy = (responsepolicy *)ksr_calloc(1,sizeof(responsepolicy));
#define SIGALG_STR "SignatureAlgorithm "
        } else if(strncasecmp(p,SIGALG_STR,sizeof(SIGALG_STR)-1) == 0) {
	  if(rppolicy) {
            char *q2;
	    sigalg *xpsigalg;
	    // Add multiple SignatureAlgorithm support    
	    xpsigalg = (sigalg *)ksr_calloc(1,sizeof(sigalg));
	    if(rppolicy->sigalg) {
	      sigalg *xp;
	      for(xp=rppolicy->sigalg;xp->next;xp=xp->next) ;
	      xp->next = xpsigalg;
	    } else {
	      rppolicy->sigalg = xpsigalg;
	    }
	    if((q2=gattr(p,"algorithm=")) == NULL) {
              logger_error("XML tag <%s> is missing attribute value for %s",p,"algorithm=");
              ksrinvalid++;
              break;
            }
            xpsigalg->algorithm = strtol(q2,&q2p,10); // Add multiple SignatureAlgorithm support
	    if(*q2p) {
	      logger_error("algorithm non numeric \"%s\"",q2);
	      ksrinvalid++;
	      free(q2);
	      break;
	    }
	    free(q2);
	  }
#define RSACMP_STR "RSA "
        } else if(strncasecmp(p,RSACMP_STR,sizeof(RSACMP_STR)-1) == 0) {
          if(rppolicy && rppolicy->sigalg) {
            char *q2;
	    sigalg *xp;
	    // Add multiple SignatureAlgorithm support
	    for(xp=rppolicy->sigalg;xp->next;xp=xp->next) ;
	    
	    if((q2=gattr(p,"size=")) == NULL) {
              logger_error("XML tag <%s> is missing attribute value for %s",
                p,"size=");
              ksrinvalid++;
              break;
            }
            xp->rsa_size = strtol(q2,&q2p,10); // Add multiple SignatureAlgorithm support
	    if(*q2p) {
	      logger_error("rsa size non numeric \"%s\"",q2);
	      ksrinvalid++;
	      free(q2);
	      break;
	    }
            free(q2);
            if((q2=gattr(p,"exponent=")) == NULL) {
              logger_error("XML tag <%s> is missing attribute value for %s",
                p,"exponent=");
              ksrinvalid++;
              break;
            }
            xp->rsa_exp = strtol(q2,&q2p,10); // Add multiple SignatureAlgorithm support
	    if(*q2p) {
	      logger_error("Exponent non numeric \"%s\"",q2);
	      ksrinvalid++;
	      free(q2);
	      break;
	    }
	    free(q2);
	  }
        }

        if(xmlparse(&lbuf[1],xs) < 0) return -1;

      } else { /* done with this tag - process data and pop-stack */
        char *p;

      xmlprocess:
        p = &lbuf[2];

        if(strncasecmp(p,tp,strlen(p)) && otag == 0) {
          logger_error("Keytag mismatch </%s> != <%s>",p,tp);
          ksrinvalid++;
          break; /* if not equal - problem */
        }

        /*myx_syslog(LOG_INFO,"tag=|%s| data=%s\n",tp,data);*/

        if(strcasecmp(p,"RequestBundle") == 0) {
          rq->incmin = rq->Inception;
          rq->expmax = rq->Expiration;
          if(xs->rqrscnt < MAX_BUNDLES) {
            xs->rqrs[xs->rqrscnt++] = rq;
          } else {
            ksrinvalid++;
            logger_error("Exceeded maximum request bundles");
          }

          rq = NULL;
        } else if(strcasecmp(p,"ResponseBundle") == 0) {
          rq->incmin = rq->Inception;
          rq->expmax = rq->Expiration;
          if(xs->rqrscnt < MAX_BUNDLES) {
            xs->rqrs[xs->rqrscnt++] = rq;
          } else {
            ksrinvalid++;
            logger_error("Exceeded maximum response bundles");
          }

          rq = NULL;
        } else if(strcasecmp(p,"Request") == 0) {

        } else if(strcasecmp(p,"PublishSafety") == 0) {
          if(rppolicy) rppolicy->PublishSafety = strdup(data);
        } else if(strcasecmp(p,"RetireSafety") == 0) {
          if(rppolicy) rppolicy->RetireSafety = strdup(data);
        } else if(strcasecmp(p,"MaxSignatureValidity") == 0) {
          if(rppolicy) rppolicy->MaxSignatureValidity = strdup(data);
        } else if(strcasecmp(p,"MinSignatureValidity") == 0) {
          if(rppolicy) rppolicy->MinSignatureValidity = strdup(data);
        } else if(strcasecmp(p,"MaxValidityOverlap") == 0) {
          if(rppolicy) rppolicy->MaxValidityOverlap = strdup(data);
        } else if(strcasecmp(p,"MinValidityOverlap") == 0) {
          if(rppolicy) rppolicy->MinValidityOverlap = strdup(data);
        } else if(strcasecmp(p,"Signer") == 0) {
          sgr->next = rq->x_sgr;
          rq->x_sgr = sgr;
          sgr = NULL;
        } else if(strcasecmp(p,"SignatureData") == 0) {
          sig->SignatureData = strdup(data);
        } else if(strcasecmp(p,"Signature") == 0) {
          sig->next = rq->x_sig;
          rq->x_sig = sig;
          sig = NULL;
        } else if(strcasecmp(p,"Key") == 0) {
          key->next = rq->x_key;
          rq->x_key = key;
          key = NULL;
        } else if(strcasecmp(p,"keyTag") == 0) {
          sig->KeyTag = strtol(data,&q2p,10);
          if(*q2p) {
            logger_error("KeyTag non numeric \"%s\"",data);
            ksrinvalid++;
          }
        } else if(strcasecmp(p,"Inception") == 0) {
          rq->Inception = ztime2sec(data);
        } else if(strcasecmp(p,"Expiration") == 0) {
          rq->Expiration = ztime2sec(data);
        } else if(strcasecmp(p,"SignersName") == 0) {
          sig->SignersName = strdup(data);
        } else if(strcasecmp(p,"Algorithm") == 0) {
          if(sig) {
	    sig->Algorithm = strtol(data,&q2p,10);
	    if(*q2p) {
	      logger_error("KeyTag non numeric \"%s\"",data);
	      ksrinvalid++;
	    }
	  } else if(key) {
	    key->Algorithm = strtol(data,&q2p,10);
	    if(*q2p) {
	      logger_error("Algorithm non numeric \"%s\"",data);
	      ksrinvalid++;
	    }
          } else { }
        } else if(strcasecmp(p,"TTL") == 0) {
          if(sig) sig->TTL = atoul(data);
          else if(key) key->TTL = atoul(data);
          else { }
        } else if(strcasecmp(p,"Flags") == 0) {
          key->Flags = strtol(data,&q2p,10);
          if(*q2p) {
            logger_error("Flags non numeric \"%s\"",data);
            ksrinvalid++;
          }
        } else if(strcasecmp(p,"Protocol") == 0) {
          key->Protocol = strtol(data,&q2p,10);
          if(*q2p) {
            logger_error("Protocol non numeric \"%s\"",data);
            ksrinvalid++;
          }
        } else if(strcasecmp(p,"Labels") == 0) {
          sig->Labels = strtol(data,&q2p,10);
          if(*q2p) {
            logger_error("Labels non numeric \"%s\"",data);
            ksrinvalid++;
          }
        } else if(strcasecmp(p,"OriginalTTL") == 0) {
          sig->OriginalTTL = strtol(data,&q2p,10);
          if(*q2p) {
            logger_error("TTL non numeric \"%s\"",data);
            ksrinvalid++;
          }
        } else if(strcasecmp(p,"SignatureInception") == 0) {
          sig->SignatureInception = ztime2sec(data);
        } else if(strcasecmp(p,"SignatureExpiration") == 0) {
          sig->SignatureExpiration = ztime2sec(data);
        } else if(strcasecmp(p,"TypeCovered") == 0) {
          sig->TypeCovered = strdup(data);
        } else if(strcasecmp(p,"PublicKey") == 0) {
          key->PublicKey = strdup(data);
        } else if(strcasecmp(p,"KSR") == 0) {
          if(debug) logger_debug("KSR end serial=\"%s\" id=\"%s\" domain=\"%s\"",xs->ksrserial,xs->ksrid,xs->ksrdomain);

        } else {
        }

        break;
      }

    } else if(i == '<' && sttg == 0) {
        sttg = 1;
        if(k > 1) {
          int j;

          j = k; /*min(k,DBUFSIZE);*/
          lbuf[j-1] = '\0';
          memcpy(data,lbuf,j);
          k = 0;
          lbuf[k++] = i;
          if(lbuf[1] == '?') otag = 1; else otag = 0;
        }
        continue;
    }
  }
  xs->depth--;
  return 0;
}

/*! parse, copy into new buffer, and return attributes in an XML tag

    \param tp the full XML tag
    \param str attribute label to search for inside tag
    \return NULL on error or ptr to new buffer with attribute if found
 */
static char *gattr(char *tp,char *str)
{
  char *q,*q2;
  int quote;

  if((q=strstr(tp,str))) {
    q += strlen(str);
    if(*q == '\0') return "";
    if(*q == '"') quote = 1; else quote = 0;
    if(quote) q++;
    q = q2 = strdup(q);
    while(1) {
      if( (quote == 1 && *q == '"' && *(q-1) != '\\')
          || (quote == 0 && *q == ' ')
          || *q == '>'
          || *q == '\0' ) {
        *q = '\0';
        return q2;
      }
      q++;
    }
  }
  logger_error("parsing \"%s\" attributes",tp);
  return NULL;
}

/*! display series of internal request/response structure

    \param rqrs array of pointers to internal request/response structures
    \param cnt number of structures to display
 */
void display_reqresp(reqresp *rqrs[],int cnt)
{
  char lbuf[MAXPATHLEN];
  int i,jj;
  reqresp *rq;
  krecord *y;

  logger_info("#  Inception           Expiration           ZSK Tags      KSK Tag(CKA_LABEL)");

  for(i=0;i<cnt;i++) {
    int cX;

    rq = rqrs[i];

    sec2ztime(rq->incmin,lbuf);
    lbuf[19] = '\0';
    myx_syslog(LOG_INFO,"%-2d %-15s",i+1,lbuf);
    sec2ztime(rq->expmax,lbuf);
    lbuf[19] = '\0';
    myx_syslog(LOG_INFO," %-15s",lbuf);

    lbuf[0] = '\0';
    cX = sizeof(lbuf);
    for(y=rq->x_key;y;y=y->next) {
      if((y->Flags & DNSKEY_SEP_FLAG)) continue;
      jj = strlen(lbuf);
      if(jj) lbuf[jj++] = ',';
      cX -= snprintf(&lbuf[jj],cX,"%05u",y->keyTag);
    }
    myx_syslog(LOG_INFO,"  %-12s",lbuf);

    lbuf[0] = '\0';
    cX = sizeof(lbuf);
#ifdef HSK_KEYS
    for(j=0;j<nksk;j++) {
      if((ksks[j]->Flags & DNSKEY_SEP_FLAG) == 0) continue;
      jj = strlen(lbuf);
      if(jj) lbuf[jj++] = ',';
      cX -= snprintf(&lbuf[jj],cX,"%05u(%s)",ksks[j]->keyTag,ksks[j]->label->p0);
    }
#else
    for(y=rq->x_key;y;y=y->next) {
      if((y->Flags & DNSKEY_SEP_FLAG) == 0) continue;
      jj = strlen(lbuf);
      if(jj) lbuf[jj++] = ',';
      cX -= snprintf(&lbuf[jj],cX,"%05u%s",y->keyTag,
                     y->Flags & DNSKEY_REVOKE_FLAG ? "/R" : "");
    }
#endif
    myx_syslog(LOG_INFO,"  %-12s",lbuf);
    myx_syslog(LOG_INFO,"\n");
  }
}

#if 0
/*! dump detailed contents of request/response structure

    \param rq pointer to internal request/response structure
 */
static void dump_requestresponse(reqresp *rq)
{
  {
    signer *s;
    for(s=rq->x_sgr;s;s=s->next)
      myx_syslog(LOG_INFO," Request KSK |%s|\n",s->keyIdentifier);
  }
  {
    krecord *y;
    for(y=rq->x_key;y;y=y->next)
      myx_syslog(LOG_INFO," Key |%s| %05u\n",y->keyIdentifier,y->keyTag);
  }
  {
    signature *s;
    for(s=rq->x_sig;s;s=s->next)
      myx_syslog(LOG_INFO," Sig |%s| %05u\n",s->keyIdentifier,s->KeyTag);
  }
}
#endif /* 0 */

/*! Free internal request/response structure and contents
    \param rq pointer to parsed internal structure
 */
void free_requestresponse(reqresp *rq)
{
  {
    signer *s,*sn;

    for(s=rq->x_sgr;s;) {
      sn = s->next;
      free_signer(s);
      s = sn;
    }
  }
  {
    krecord *s,*sn;

    for(s=rq->x_key;s;) {
      sn = s->next;
      free_keyrecord(s);
      s = sn;
    }
  }
  {
    signature *s,*sn;

    for(s=rq->x_sig;s;) {
      sn = s->next;
      free_signature(s);
      s = sn;
    }
  }

  if(rq->id) free(rq->id);

  free(rq);
}

/*! Free internal key record structure and contents
    \param s internal key record structure
 */
void free_keyrecord(krecord *s)
{
  if(s == NULL) return;
  if(s->keyIdentifier) free(s->keyIdentifier);
  if(s->PublicKey) free(s->PublicKey);
  if(s->user) free(s->user);
  if(s->modulus) mbuf_free(s->modulus);
  if(s->pubexp) mbuf_free(s->pubexp);
  if(s->label) mbuf_free(s->label);
  if(s->pkcb) pkcs11_free_pkkeycb(s->pkcb);
  free(s);
}
/*! Free internal signature structure and contents

    \param s internal signature structure
 */
static void free_signature(signature *s)
{
  if(s->keyIdentifier) free(s->keyIdentifier);
  if(s->TypeCovered) free(s->TypeCovered);
  if(s->SignersName) free(s->SignersName);
  if(s->SignatureData) free(s->SignatureData);
  free(s);
}
/*! Free internal signer structure and contents
    \param s internal signer structure
 */
static void free_signer(signer *s)
{
  if(s->keyIdentifier) free(s->keyIdentifier);
  free(s);
}
/*! Free internal response policy structure and contents
    \param s internal response policy structure
 */
static void free_responsepolicy(responsepolicy *r)
{
  if(r->PublishSafety) free(r->PublishSafety);
  if(r->RetireSafety) free(r->RetireSafety);
  if(r->MaxSignatureValidity) free(r->MaxSignatureValidity);
  if(r->MinSignatureValidity) free(r->MinSignatureValidity);
  if(r->MaxValidityOverlap) free(r->MaxValidityOverlap);
  if(r->MinValidityOverlap) free(r->MinValidityOverlap);
  if(r->sigalg) {
    sigalg *xp,*xpn;
    for(xp=r->sigalg;xp;) { // Add multiple SignatureAlgorithm processing
      xpn = xp->next;
      free(xp);
      xp = xpn;
    }
  }
  free(r);
}

/*! Return (XML-format-days) - (days). Support for testing RequestPolicy

   \param xst pointer to XML formated days. e.g. PxD x days
   \param days
   \return (XML-format-days) - (days)
*/
static int xmltimecmp(char *xst,int days)
{
  int dout;
  if(xst == NULL) return 0; // accept if not specified since this does not effect DNSKEY RRset
  dout = 0;
  sscanf(xst,"P%dD",&dout);
  if(debug) logger_info("%s: %d - %d",__func__,dout,days);
  return dout - days;
}
/*! Check RequestPolicy and Other sections of KSR.  Note:Has no effect on resultant DNSKEY RRSet

    \param rq pointer to parsed request
    \return 0 but global variable ksrinvalid is incremented for each error
*/
static int check_requestpolicy(reqresp *rq)
{
  static reqresp *last_rq=NULL;

  if(last_rq) { // Test RRSIG overlap of RequestBundles (Other)
    // On subsequent passes check T_MIN/MAX_VALIDITY_OVERLAP - MUST BE SEQUENTIAL RequestBundles
    time_t li;
    if(rq->Inception > last_rq->Expiration) {
      logger_error("Signatures do not overlap");
      ksrinvalid++;
    }
    li = (1 + last_rq->Expiration - rq->Inception)/T_ONEDAY;
    if(debug) logger_info("Overlap = %d",li);
    if(li < T_MIN_VALIDITY_OVERLAP || li > T_MAX_VALIDITY_OVERLAP) {
      logger_error("Overlap period out of policy %d days",li);
      ksrinvalid++;
    }
  }

  last_rq = rq; // first pass so set last_rq for subsequent sequential overlap comparison

  // Check stated VRSN ZSK RequestPolicy to see if they match specs.
  // Not used in results (DNSKEY RRsets) except to check VRSN's own work.
  // We enforce actual param limits on keys+sigs in later section.
  if(xmltimecmp(rppolicy->PublishSafety,T_PUBLISH_SAFETY) < 0) {
    logger_error("ZSK POLICY: Bad PublishSafety (%s)",rppolicy->PublishSafety);
    ksrinvalid++;
  }
  if(xmltimecmp(rppolicy->RetireSafety,T_RETIRE_SAFETY) > 0) {
    logger_error("ZSK POLICY: Bad RetireSafety (%s)",rppolicy->RetireSafety);
    ksrinvalid++;
  } 
  // ICANN controls this since we are the signer - see original code later
  // if(li > (T_MAX_SIG_VAL*T_ONEDAY) || (li+1) < (T_MIN_SIG_VAL*T_ONEDAY))  15-20 days
  if(xmltimecmp(rppolicy->MaxSignatureValidity,T_MAX_SIG_VAL)) { // match
    logger_error("ZSK POLICY: Bad MaxSignatureValidity (%s)",rppolicy->MaxSignatureValidity);
    ksrinvalid++;
  }  
  if(xmltimecmp(rppolicy->MinSignatureValidity,T_MIN_SIG_VAL)) { // match
    logger_error("ZSK POLICY: Bad MinSignatureValidity (%s)",rppolicy->MinSignatureValidity);
    ksrinvalid++;
  }
  if(xmltimecmp(rppolicy->MaxValidityOverlap,T_MAX_VALIDITY_OVERLAP) > 0) {
    logger_error("ZSK POLICY: Bad MaxValidityOverlap (%s)",rppolicy->MaxValidityOverlap);
    ksrinvalid++;
  }  
  if(xmltimecmp(rppolicy->MinValidityOverlap,T_MIN_VALIDITY_OVERLAP) < 0) {
    logger_error("ZSK POLICY: Bad MinValidityOverlap (%s)",rppolicy->MinValidityOverlap);
    ksrinvalid++;
  }

  // Test ZSK Key parameters (Other) against VRSN stated policies (RequestPolicy)
  {
    sigalg *xp;
    uint32_t rsa_exp;
    int n;
    uint8_t *p;
    krecord *y;
    
    for(y=rq->x_key;y;y=y->next) {      
      p = y->pubexp->p0;
      n = (int)(y->pubexp->pc - p);
      rsa_exp = 0;
      if(n > 4) {
	logger_error("Unsupported exponent length (%d)",n);
	ksrinvalid++;
      } else {
	for(;n>0;n--) rsa_exp = (rsa_exp<<8)|*p++;
      }
      if(debug) logger_info("alg:%d size:%d exp:%d",y->Algorithm,y->bits,rsa_exp);
      for(xp=rppolicy->sigalg;xp;xp=xp->next) { // walk RequestPolicy SignatureAlgorithm and compare
	if(debug) logger_info("  alg=%d size=%d exp=%d",xp->algorithm,xp->rsa_size,xp->rsa_exp);
	if(y->Algorithm == xp->algorithm && y->bits == xp->rsa_size
	   && rsa_exp == (uint32_t)xp->rsa_exp) break;
      }
      if(xp == NULL) { // no matches
	logger_error("ZSK does not match any xml ZSK SignatureAlgorithm");
	ksrinvalid++;
      }
      // no effect on DNSKEY RRset result but check VRSN xml "keytag" match while at it
      if(y->keyTag != updatekeytag(y)) {
	logger_error("ZSK xml keytag and actual keytag do not match (%d != %d)",
		     y->keyTag,updatekeytag(y));
	ksrinvalid++;
      }
    }
  }

  return 0;
}

/*! Check if request is valid (e.g., algorithms, protocols, validity period,
    proof of private key ownership, etc..)

    \param rq pointer to parsed request
    \param ksrdomain domain name associated with this request
    \return 0 but global variable ksrinvalid is incremented for each error
*/
int check_requestbundle(reqresp *rq,char *ksrdomain)
{
  int keycnt;

  if(debug) {
    signer *s;
    logger_info("RequestBundle id=%s",rq->id);
    for(s=rq->x_sgr;s;s=s->next) 
      logger_info(" Request KSK |%s|",s->keyIdentifier);
  }
  {
    krecord *y;

    keycnt = 0;
    for(y=rq->x_key;y;y=y->next) {
      if(algtohash(y->Algorithm) < 0) {
        logger_error("Unsupported key algorithm (%d)",y->Algorithm);
        ksrinvalid++;
      }
      if((y->Flags & DNSKEY_SEP_FLAG)) {
        logger_error("SEP bit set on ZSK flag=%d",y->Flags);
        ksrinvalid++;
      }
      if(y->Protocol != DNSKEY_PROTOCOL_DNSSEC) {
        logger_error("Unsupported protocol (%d) for ZSK",y->Protocol);
        ksrinvalid++;
      }
      if(debug) logger_debug("Key |%s| %05u",y->keyIdentifier,y->keyTag);

      fillinpinfo(y);

      keycnt++;
    }
    if(keycnt <= 0) {
      logger_error("No keys found in KSR");
      ksrinvalid++;
    }
    if(keycnt >= MAX_KEYS) {
      logger_error("Number of keys exceeded %d >= %d",keycnt,MAX_KEYS);
      ksrinvalid++;
    }
  }
  {
    signature *s;
    keycnt = 0;
    for(s=rq->x_sig;s;s=s->next) {
      if(algtohash(s->Algorithm) < 0) {
        logger_error("Unsupported signature algorithm (%d)",s->Algorithm);
        ksrinvalid++;
      }
      if(strcmp(s->TypeCovered,"DNSKEY")) {
        logger_error("Unsupported Type Covered %s by signature",s->TypeCovered);
        ksrinvalid++;
      }
      if(strcmp(s->SignersName,ksrdomain)) {
        logger_error("SignersName (%s) != domain",s->SignersName);
        ksrinvalid++;
      }
      if(debug) logger_debug("Sig |%s| %05u",s->keyIdentifier,s->KeyTag);
      keycnt++;
    }
    if(keycnt <= 0) {
      logger_error("No signatures found in KSR");
      ksrinvalid++;
    }
  }

  if(rq->Expiration > maxexpiration) {
    /* Changed from error to warning in DVD r600 to provide flexibility to personnel scheduling.
       Previously limited rq->Expiration to maxexpiration and incremented ksrinvalid. */
    logger_warning("*** Requests signature expiration exceeds limit of %d days! ***",(T_VLIMIT+1));
  }

  if(rq->Inception >= rq->Expiration) {
    char t0buf[30],t1buf[30];

    sec2ztime(rq->Inception,t0buf);
    sec2ztime(rq->Expiration,t1buf);
    logger_error("Inception and Expiration times (%s - %s) do not allow for "
      "key bundle generation.", t0buf, t1buf);
    ksrinvalid++;
  }

#ifdef WEDOESLOTS  /* we calculate periods for key bundle slots */
  /* we will automatically enforce */
#else /* The KSR tells us the slots periods - check here */
  {
    time_t li;
    li = rq->Expiration - rq->Inception;
    if(li > (T_MAX_SIG_VAL*T_ONEDAY) || (li+1) < (T_MIN_SIG_VAL*T_ONEDAY)) {
      logger_error("Requested validity period (%u sec) out of policy",li);
      ksrinvalid++;
    }
  }
#endif

  check_requestpolicy(rq); // Add check of RequestPolicy. Note: This has no effect on resultant DNSKEY RRset
  
  if(ksrinvalid) goto enderror;

  /*
   * Verify KSR[n] ZSK RRSIGs - Proof of Possesion
   */
  keycnt = 0;
  {
    signature *s;

    for(s=rq->x_sig;s;s=s->next) {
      if(validatekeybundle(s,rq->x_key)) {
        logger_error("Could not verify key with identifier %s",
          s->keyIdentifier);
        ksrinvalid++;
        goto enderror;  /* if any error - exit */
      }
      if(debug)
        logger_info("Verified private key ownership for %05u",s->KeyTag);
#ifdef VALIDATE_VALIDITY
      /* find max VALIDATED expiration and inception time */
      if(s->SignatureExpiration > rq->expmax) 
        rq->expmax = s->SignatureExpiration;
      if(s->SignatureInception < rq->incmin)
        rq->incmin = s->SignatureInception;
#endif
      keycnt++;
    }
  }
  if(keycnt == 0) {
    logger_error("No valid keys in key bundle");
    ksrinvalid++;
    goto enderror;
  }
  
  /*
   * Check other parameters and policy and signature lifetimes
   * ===== most done prior to here ====
   */

 enderror:
  if(debug) logger_info("=====");
  return 0;
}

/*! For REVOKE bit only, clearly should just backout and reinsert 
    the REVOKE bit but recalculating was easier.

    \param kr  key record to recalculate keytag over
    \return 16-bit keytag
*/
static uint16_t updatekeytag(krecord *kr)
{
  uint8_t *q,lbuf[4098];
  int n;

  q = lbuf;
  *(uint16_t *)q = htons(kr->Flags);
  q += 2;
  *(uint8_t *)q = (uint8_t)kr->Protocol;
  q++;
  *(uint8_t *)q = (uint8_t)kr->Algorithm;
  q++;
  n = (int)(kr->pubexp->pc - kr->pubexp->p0);
  *q++ = (uint8_t)n;
  memcpy(q,kr->pubexp->p0,n);
  q += n;
  n = (int)(kr->modulus->pc - kr->modulus->p0);
  memcpy(q,kr->modulus->p0,n);
  q += n;
  return dnssec_keytag(lbuf,(int)(q-lbuf));
}
/*! Sign the request

    \param xs struct containing parsed validated request and signing key data
    \param ftmp file pointer to write signed response in XML format to.
    \return -1 if error; 0 if ok
 */
int signem(FILE *ftmp,xmlstate *xs)
{
  krecord *keys[MAX_KEYS];
  int keycnt,i,ir,ret;
  reqresp *rq,**reqs;
  int reqscnt;

  ret = -1;
  if(debug) logger_debug("Signem");

  reqs = xs->rqrs;
  reqscnt = xs->rqrscnt;

  fprintf(ftmp,"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
  fprintf(ftmp,"<KSR id=\"%s\" domain=\"%s\" serial=\"%s\">\n",xs->ksrid,xs->ksrdomain,xs->ksrserial);
  fprintf(ftmp,"<Response>\n");
  
  fprintf(ftmp,"<ResponsePolicy>\n");
  
  fprintf(ftmp,"<KSK>\n");
  fprintf(ftmp,"<PublishSafety>PT%dS</PublishSafety>\n", T_PUBLISH_SAFETY);
  fprintf(ftmp,"<RetireSafety>P%uD</RetireSafety>\n",T_RETIRE_SAFETY);
  fprintf(ftmp,"<MaxSignatureValidity>P%uD</MaxSignatureValidity>\n",T_MAX_SIG_VAL);
  fprintf(ftmp,"<MinSignatureValidity>P%uD</MinSignatureValidity>\n",T_MIN_SIG_VAL);
  fprintf(ftmp,"<MaxValidityOverlap>P%uD</MaxValidityOverlap>\n",T_MAX_VALIDITY_OVERLAP);
  fprintf(ftmp,"<MinValidityOverlap>P%uD</MinValidityOverlap>\n",T_MIN_VALIDITY_OVERLAP);
  fprintf(ftmp,"<SignatureAlgorithm algorithm=\"%d\">\n",KSK_RRSIG_ALG);
  fprintf(ftmp,"<RSA size=\"%d\" exponent=\"%d\"/>\n", KSK_RRSIG_RSA_KEYSIZE, KSK_RRSIG_RSA_EXPONENT);
  fprintf(ftmp,"</SignatureAlgorithm>\n");
  fprintf(ftmp,"</KSK>\n");

  if(rppolicy) {
    fprintf(ftmp,"<ZSK>\n");
    if(rppolicy->PublishSafety) fprintf(ftmp,"<PublishSafety>%s</PublishSafety>\n",rppolicy->PublishSafety);
    if(rppolicy->RetireSafety) fprintf(ftmp,"<RetireSafety>%s</RetireSafety>\n",rppolicy->RetireSafety);
    if(rppolicy->MaxSignatureValidity) fprintf(ftmp,"<MaxSignatureValidity>%s</MaxSignatureValidity>\n",rppolicy->MaxSignatureValidity);
    if(rppolicy->MinSignatureValidity) fprintf(ftmp,"<MinSignatureValidity>%s</MinSignatureValidity>\n",rppolicy->MinSignatureValidity);
    if(rppolicy->MaxValidityOverlap) fprintf(ftmp,"<MaxValidityOverlap>%s</MaxValidityOverlap>\n",rppolicy->MaxValidityOverlap);
    if(rppolicy->MinValidityOverlap) fprintf(ftmp,"<MinValidityOverlap>%s</MinValidityOverlap>\n",rppolicy->MinValidityOverlap);
    if(rppolicy->sigalg) {
      sigalg *sa;
      // Add support for multiple SignatureAlgorithms in ResponsePolicy. Note: This has no effect on resultant DNSKEY RRset
      for(sa=rppolicy->sigalg;sa;sa=sa->next) {
	fprintf(ftmp,"<SignatureAlgorithm algorithm=\"%d\">\n",sa->algorithm);
	fprintf(ftmp,"<RSA size=\"%d\" exponent=\"%d\"/>\n",sa->rsa_size,sa->rsa_exp);
	fprintf(ftmp,"</SignatureAlgorithm>\n");
      }
    }
    fprintf(ftmp,"</ZSK>\n");
  }
  
  fprintf(ftmp,"</ResponsePolicy>\n");

  if(ksklabel_2) {
    if(reqscnt < MIN_SLOTS_FOR_KSK_ROLL) {
      logger_error("Do not have enough slots to roll KSK");
      ksrinvalid++;
      goto enderror;
    }
  }

  /* reqs[] is now a sorted list */
  for(ir=0;ir<reqscnt;ir++) {
    rq = reqs[ir];
    keycnt = 0;
    /*
     * pick KSK's to sign with
     */
    if(revoke_all) {
      for(i=0;i<nksk;i++) {
        if(
	   (
	    (ksklabel_1 && strcmp((char *)ksks[i]->label->p0,ksklabel_1) == 0)
	    || 
	    (ksklabel_2 && strcmp((char *)ksks[i]->label->p0,ksklabel_2) == 0)
	    )
	   && pkcs11_have_private_key(ksks[i]->pkcb) 
	   ) {
          keys[keycnt++] = ksks[i];
	  ksks[i]->Flags |= DNSKEY_REVOKE_FLAG;
	  ksks[i]->keyTag = updatekeytag(ksks[i]);
          ksks[i]->signer = 1;
        }
      }
    } else
    if(ksklabel_2) { /* KSK rollover */
      /*
       * ir = 0-5 sign /w ksklabel_1
       * ir = 6-7 revoke bit and sign /w ksklabel_1
       * ir = 8 do not include
       *
       * ir = 0 do not include
       * ir = 1-5 just include ksklabel_2
       * ir = 6-8 sign /w ksklabel_2
       */
      for(i=0;i<nksk;i++) {
        ksks[i]->signer = 0; /* clear prior use */
        if(ksks[i]->user) { /* will need to recalc wire fmt for REVOKE flg */
          free(ksks[i]->user);
          ksks[i]->user = NULL;
        }
        ksks[i]->Flags &= ~DNSKEY_REVOKE_FLAG; /* clear prior use */
        ksks[i]->keyTag = updatekeytag(ksks[i]);
        if(strcmp((char *)ksks[i]->label->p0,ksklabel_1) == 0
           && pkcs11_have_private_key(ksks[i]->pkcb)) {
          if(ir >= 0 && ir <= 7) {
            keys[keycnt++] = ksks[i];
            ksks[i]->signer = 1;
            if(ir == 6 || ir == 7) {
              ksks[i]->Flags |= DNSKEY_REVOKE_FLAG;
              ksks[i]->keyTag = updatekeytag(ksks[i]);
            }
          }
        } else
        if(strcmp((char *)ksks[i]->label->p0,ksklabel_2) == 0
           && pkcs11_have_private_key(ksks[i]->pkcb) ) {
          if(ir >= 1 && ir <= 8) {
            keys[keycnt++] = ksks[i];
            if(ir >= 6 && ir <= 8) ksks[i]->signer = 1;
          }
        }
      }
    } else
    if(ksklabel_1) { /* use specified KSK */
      for(i=0;i<nksk;i++) {
	/* make sure we are not operating off a mismatched AEP/DB pair */
        if(strcmp((char *)ksks[i]->label->p0,ksklabel_1) == 0
           && pkcs11_have_private_key(ksks[i]->pkcb) ) {
          keys[keycnt++] = ksks[i];
          ksks[i]->signer = 1;
        }
      }
    } else
    if(rq->x_sgr) { /* use ones specified by KSR */
      signer *s;
      for(i=0;i<nksk;i++) {
        for(s=rq->x_sgr;s;s=s->next) {
          if(strcmp(s->keyIdentifier,ksks[i]->keyIdentifier) == 0) {
            if(debug) logger_debug("Signing with KSK |%s|",s->keyIdentifier);
            keys[keycnt++] = ksks[i];
            if( pkcs11_have_private_key(ksks[i]->pkcb) ) ksks[i]->signer = 1;
            break;
          }
        }
      }
    } else { /* sign with all */
      for(i=0;i<nksk;i++) {
        keys[keycnt++] = ksks[i];
        if( pkcs11_have_private_key(ksks[i]->pkcb) ) ksks[i]->signer = 1;
      }
    }
    
    if(keycnt == 0) {
      logger_error("Can't find requested KSK to sign with");
      ksrinvalid++;
      goto enderror;
    }

    /* 
     * add ZSKs to sign
     */
    {
      krecord *y;
      
      for(y=rq->x_key;y;y=y->next) {
        /*
         * need to start /w fresh context since rrsig()
         * uses different TTL than validatebundle()
         */
        if(y->user) {
          free(y->user);
          y->user = NULL;
        }
        keys[keycnt++] = y;
      }
    }
  
    /*
     * compute RRSIGs
     */
    fprintf(ftmp,"<ResponseBundle id=\"%s\">\n",rq->id);
    {
      time_t t,tmax;
      int showkeys;
      char t0buf[30],t1buf[30];
      
      t = rq->incmin;
      tmax = rq->expmax;
      sec2ztime(t,t0buf);
      sec2ztime(tmax,t1buf);
      fprintf(ftmp,"<Inception>%s</Inception>\n",t0buf);
      fprintf(ftmp,"<Expiration>%s</Expiration>\n",t1buf);
      showkeys = 1;
      
#ifdef WEDOESLOTS
      while(t < tmax) {
        
        sec2ztime(t,t0buf);
        sec2ztime(t+validityperiod,t1buf);
        printf("Returned: %s to %s\n",t0buf,t1buf);
        
        if(rrsig(keys,keycnt,xs->ksrdomain,t,t+validityperiod,&showkeys,ftmp)) {
          ksrinvalid++;
          goto enderror;
        }
        t += t_step;
      }
#else
      if(rrsig(keys,keycnt,xs->ksrdomain,t,tmax,&showkeys,ftmp)) ksrinvalid++;
#endif
      
    }
    fprintf(ftmp,"</ResponseBundle>\n"); 
  }
  fprintf(ftmp,"</Response>\n");
  fprintf(ftmp,"</KSR>\n");
  ret = 0;
  
 enderror:
  if(debug) logger_debug("=====");
  return ret;
}
/*! Check response has valid keys and prove it was generated from 
    private key inside HSM.  This is used validate the prior SKR 
    in the trust chain.

    \param rq pointer to request structure
    \return -1 if error; 0 if ok.  Also increments global ksrinvalid on each error
 */
int check_responsebundle(reqresp *rq)
{
  int any;

  if(debug) logger_debug("ResponseBundle id=%s",rq->id);

  {
    krecord *y;
    int keycnt;

    keycnt = 0;
    for(y=rq->x_key;y;y=y->next) {
      if(debug) logger_debug("Key |%s| %05u",y->keyIdentifier,y->keyTag);
      keycnt++;

      fillinpinfo(y);

    }
    if(keycnt >= MAX_KEYS) {
      logger_error("Number of keys exceeded %d >= %d", keycnt, MAX_KEYS);
      ksrinvalid++;
    }
  }
  {
    signature *s;
    for(s=rq->x_sig;s;s=s->next) {
      if(debug) logger_debug("Sig |%s| %05u",s->keyIdentifier,s->KeyTag);
    }
  } 
  
  if(ksrinvalid) goto enderror;
  
  /*
   * Verify SKR[n-1] KSK RRSIGs using PRIVATE KSK
   */
  any = 0;
  {
    signature *s;
    krecord *y;
    
    for(s=rq->x_sig;s;s=s->next) {
      for(y=rq->x_key;y;y=y->next) {
        if(strcmp(y->keyIdentifier,s->keyIdentifier) == 0) {
          if((y->Flags & DNSKEY_SEP_FLAG) == 0) {
            logger_error("Key is not marked as KSK (flag=%d)",y->Flags);
            ksrinvalid++;
            goto endkeytest;
          }
          break;
        }
      }
      if(y == NULL) {
        logger_error("No matching signature found for key %s",s->keyIdentifier);
        ksrinvalid++;
        goto endkeytest;
      }
      if(validatekeybundle(s,rq->x_key)) { /* uses HSM priv for KSK */
        logger_error("Could not verify signature with keytag %05u",s->KeyTag);
        ksrinvalid++;
        goto endkeytest;  /* if any error - exit */
      }
      if(debug) logger_debug("Validated signature made with %05u",s->KeyTag);
#ifdef VALIDATE_VALIDITY
      if(s->SignatureExpiration > rq->expmax)
        rq->expmax = s->SignatureExpiration;
      if(s->SignatureInception < rq->incmin)
        rq->incmin = s->SignatureInception;
#endif
      any++;
    }
  }
  if(any == 0) {
    logger_error("No valid keys in key bundle");
    goto endkeytest;
  }

 enderror:
  if(debug) logger_debug("=====");
  return 0;

 endkeytest:
  ksrinvalid++;
  if(debug) logger_debug("=====");
  return -1;
}
/*! Function used by qsort to order RRSIGs by expiration date

    \param a,b  void cast request/response pointers
    \return -1 if expiration time a < b else return 1
 */
int expmaxcmpr(const void *a,const void *b)
{
  reqresp * const *d1 = a;
  reqresp * const *d2 = b;
  time_t t1,t2;
  t1 = (*d1)->expmax;
  t2 = (*d2)->expmax;
  if(t1 < t2) return -1;
  return 1;
}

/*! Convert XML time format to time() seconds format

    \param s string with time struct
    \return seconds in time() equivalent
 */
static time_t ztime2sec(char *s)
{
  /* 2009-06-01T00:00:00Z or 2009-06-01T00:00:00.*+00:00 */
  char *p,cc[30];
  int i;
  struct tm _t,*t;

  if(s == NULL) {
    logger_error("NULL ztime string");
    return 0;
  }
  if(s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':') {
    logger_error("Invalid time format \"%s\"",s);
    return 0;
  }
  if(s[19] && s[19] != 'Z') {
    char *p,*q;

    q = &s[19];
    if( ((p=strchr(q,'+')) == NULL && (p=strchr(q,'-')) == NULL) 
        || strcmp(p+1,"00:00")) {
      logger_error("Invalid time format \"%s\" - must be UTC.",s);
      return 0;
    }
  }

  strlcpy(cc,s,sizeof(cc));
  cc[19] ='\0';
  t = &_t;
  memset(t,0,sizeof(struct tm));

  i = strtol(&cc[17],&p,10); if(*p) goto err;
  t->tm_sec = i; cc[16] = '\0';
  if(t->tm_sec < 0 || t->tm_sec > 60) goto err;

  i = strtol(&cc[14],&p,10); if(*p) goto err;
  t->tm_min = i; cc[13] = '\0';
  if(t->tm_min < 0 || t->tm_min > 59) goto err;

  i = strtol(&cc[11],&p,10); if(*p) goto err;
  t->tm_hour = i; cc[10] = '\0';
  if(t->tm_hour < 0 || t->tm_hour > 23) goto err;

  i = strtol(&cc[8],&p,10); if(*p) goto err;
  t->tm_mday = i; cc[7] = '\0';
  if(t->tm_mday < 1 || t->tm_mday > 31) goto err;

  i = strtol(&cc[5],&p,10); if(*p) goto err;
  t->tm_mon = i - 1; cc[4] = '\0';
  if(t->tm_mon < 0 || t->tm_mon > 11) goto err;

  i = strtol(&cc[0],&p,10); if(*p) goto err;
  if(i < 2009) goto err;
  t->tm_year = i - 1900;

  t->tm_isdst = 0; /* since we are passing in UTC, assume none */

  return timegm(t);
 err:
  logger_error("in %s: invalid ztime |%s|",__func__,s);
  return 0;
}

/*! Fill in general purpose info for a non-HSM key

    \param kr partially filled in key record structure
    \return 0 if success
 */
static int fillinpinfo(krecord *kr)
{
  int i,n;
  uint8_t *p,wire[4096];
  mbuf *bp;

  if(kr->modulus == NULL) {
    n = base64decode(kr->PublicKey,wire,sizeof(wire));
    p = wire;
    i = *p++;
    n--;
    bp = alloc_mbuf(i);
    memcpy(bp->p0,p,i);
    bp->pc += i;
    p += i;
    n -= i;
    kr->pubexp = bp;
    bp = alloc_mbuf(n);
    memcpy(bp->p0,p,n);
    bp->pc += n;
    kr->modulus = bp;

    kr->bits = n*8;
  }
  return 0;
}


/******************************************************************
 * DNSSEC/DNS support
 ******************************************************************/

/*! Return number of levels in domain name

    \param dn string containing domain name
    \return number of '.'s
*/
int dndepth(char *dn)
{
  int n,m;
  uint8_t *p;

  n = 0;
  m = 0;
  for(p=(uint8_t *)dn;*p;p++) {
    if(*p == '.') {
      if(n > 0) m++;
      n = 0;
      continue;
    }
    n++;
  }
  return m;
}
/*! Return hash corresponding to DNSSEC signing algorithm type

    \param alg DNSSEC signing algorithm number
    \return internal hash type or -1 if unsupported algorithm
*/
int algtohash(int alg)
{
  switch(alg) {
  case RRSIG_RSASHA1:
  case RRSIG_RSANSEC3SHA1:
    return HASH_SHA1;
  case RRSIG_RSASHA256:
    return HASH_SHA256;
  default:
    return -1;
  }
}

