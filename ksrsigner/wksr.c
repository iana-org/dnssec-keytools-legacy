/*
 * $Id: wksr.c 567 2010-10-28 05:11:10Z jakob $
 *
 * Copyright (c) 2007 Internet Corporation for Assigned Names ("ICANN")
 * Copyright (c) 2006 Richard H. Lamb ("RHL") slamb@xtcn.com
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

#include <stdint.h>

#include "util.h"
#include "logger.h"
#include "ksrcommon.h"
#include "ksrpolicy.h"
#include "dnssec.h"
#include "compat.h"

#define LOGDIR "../logs"

static const char *progname = "wksr";

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
static char skr_keybundle_template[MAXPATHLEN];
static int testitbcnt=0;
static time_t t_now;
static char basedir[MAXPATHLEN];
static char nowstr[30];
static char *remoteaddr;
static char *month2string[]={"JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC",(char *)0};
#define TEMPLATEFILE "template.html"
static char bodytag[]="#CONTENTS";
static char dntag[]="#CLIENTDN";
static char datetag[]="#MYDATE";
static char copyyeartag[]="#COPYYEAR";

static int rxupload(FILE *fin,uint32_t clen);
static int prevalidate(FILE *fout);

/*! wksr main

    Called by web server as a cgi to respond to KSR submissions. Does first
    pass of validatinf submission and responds with properly formatted (but
    dummy key) response. No need for HSM. assumes client side SSL
    authentication has been successuffly completed by web server. The
    following environment variables are read:

    REMOTE_ADDR, HTTP_VIA, SSL_CLIENT_S_DN
    REQUEST_METHOD, CONTENT_TYPE, CONTENT_LENGTH, HTTP_HOST, SCRIPT_NAME

    \param argc argument count
    \param *argv[] pointer to args described above
    \return -1 on error; else 0
 */
int main(int argc,char *argv[])
{
  int ret,sawpost,ctypok;
  uint32_t clen;
  char *p,*host,*url,*clientdn;
  char buf[LBUFLEN];
  struct tm *t2,_t2;
  FILE *fp;
  int i;

  for(i=1;i<argc;i++) {
    if(strcmp(argv[i],"-V") == 0) {
      printf("%s %s version %s\n", PACKAGE_TARNAME, progname, PACKAGE_VERSION);
      exit(0);
    }
  }

  ret = -1;

  /* Note current time */
  time(&t_now);
  gmtstrtime(t_now, nowstr);

  /* Initialization */
  strlcpy(basedir,argv[0],sizeof(basedir));
  if((p=strrchr(basedir,'/'))) {
    *p++ = '\0';
  } else {
    strlcpy(basedir,".",sizeof(basedir));
    p = argv[0];
  }
  strcat(basedir,"/.."); /* for last skr and template */

  /* Init log system and say hello to the auditors */
  logger_init(progname, LOGDIR, LOG_EMPTY);
  logger_hello(argc, argv);

  t2 = &_t2;
  memcpy(t2,gmtime(&t_now),sizeof(struct tm));

  setbuf(stdout,NULL);

  printf("pragma: no-cache%ccache-control: no-cache%c",10,10);
  printf("expires: 25-DEC-1980 12:00:00 GMT%c",10);
  printf("Content-type: text/html\n");
  printf("\n");

  if((p=getenv("REMOTE_ADDR")) == NULL) {
    logger_error("I cannot verify an incoming network address");
    goto endit;
  }
  remoteaddr = strdup(p);
  if((p=getenv("HTTP_VIA"))) {
    char *q;
    int n;

    n = strlen(remoteaddr) + strlen(p) + 20;
    q = (char *)malloc(n);
    snprintf(q,n,"%s via %s",remoteaddr,p);
    free(remoteaddr);
    remoteaddr = q;
  }
  logger_info("Connection from %s",remoteaddr);

  if((p=getenv("SSL_CLIENT_S_DN")) == NULL) {
    logger_error("No SSL_CLIENT_S_DN. Client must be authenticated");
    goto endit;
  }
  clientdn = strdup(p);

  sawpost = 0;
  ctypok = 0;
  clen = 0;
  if((p=getenv("REQUEST_METHOD")) && strcmp(p,"POST") == 0) sawpost = 1;
  if((p=getenv("CONTENT_TYPE")) && strstr(p,"multipart/form-data")) ctypok = 1;
  if((p=getenv("CONTENT_LENGTH"))) sscanf(p,"%u",&clen); /* CVTY */
  if((p=getenv("HTTP_HOST"))) host = strdup(p); else host = "";
  if((p=getenv("SCRIPT_NAME"))) url = strdup(p); else url = "/";
  {
    char *method,*ctype;
    int i;
    if((p=getenv("REQUEST_METHOD")) == NULL) p = "-";
    method = strdup(p);
    if((p=getenv("CONTENT_TYPE")) == NULL) p = "-";
    ctype = strdup(p);
    logger_info("|%s|%s|%s|%s|%lu|",host,url,method,ctype,clen);
    for(i=0;i<argc;i++) logger_info(" %d |%s|",i,argv[i]);
    free(method);
    free(ctype);
  }

  /* anything else - assume home page */
  snprintf(buf,sizeof(buf),"%s/%s",basedir,TEMPLATEFILE);
  if((fp=fopen(buf,"r")) == NULL) {
    logger_error("Cannot open template %s/%s",basedir,TEMPLATEFILE);
    goto endit;
  }
  while(fgets(buf,sizeof(buf),fp)) {
    if(strncmp(buf,bodytag,sizeof(bodytag)-1) == 0) {

      printf("<br>\n");

      if(argc > 1) p = argv[1]; else p = NULL;
      if(sawpost) {
        printf("<pre>\n");
        if(p && strncasecmp(p,"upload\\&",8) == 0) {
          /*printf("%s %u\n",&p[8],clen);*/
          logger_info("%s %u",&p[8],clen);
          /*void logger_setflags(int flags);*/
          logger_stdout_enable();
          rxupload(stdin,clen);
          logger_stdout_disable();
        } else if(p && strncasecmp(p,"submit\\&",8) == 0) {
          printf("rxsubmit(stdin,stdout,&p[8]);\n");
        } else {
          logger_error("Unknown POST");
        }
        printf("</pre>\n");
      } else if(p && strncasecmp(p,"status\\&",8) == 0) {
        printf("<pre>\n");
        printf("txstatus(stdin,stdout,&p[8]);\n");
        printf("</pre>\n");
      } else {

      printf("<script type=\"text/javascript\">\n");
      printf("function jsUpload(upload_field) {\n");
      printf("upload_field.form.submit();\n");
      printf("return true;\n");
      printf("}\n");
      printf("function jsReload(url) {\n");
      printf("location.href=url;\n");
      printf("return true;\n");
      printf("}\n");
      printf("</script>\n");

      printf("<form action=\"%s?upload&ksr\" method=\"post\" enctype=\"multipart/form-data\" style=\"display: inline; margin: 0\">\n",url);
      printf("<input type=\"file\" name=\"file\" id=\"file\" onChange=\"jsUpload(this)\" size=\"43\">\n");
      printf("</form>\n");
      /*homepg();*/

      }

    } else if(strncmp(buf,dntag,sizeof(dntag)-1) == 0) {
      printf("%s\n",clientdn);
    } else if(strncmp(buf,datetag,sizeof(datetag)-1) == 0) {
      printf("%02u-%s-%04u %02u:%02u UTC\n",t2->tm_mday,month2string[t2->tm_mon],t2->tm_year+1900,t2->tm_hour,t2->tm_min);
    } else if(strncmp(buf,copyyeartag,sizeof(copyyeartag)-1) == 0) {
      printf("%04u\n",t2->tm_year+1900);
    } else {
      printf("%s",buf);
    }
  }
  fclose(fp);

 endit:

  logger_info("done");

  return 0;
}

/*! Process incomming POST comming in on fin

    Does all the work including schema validation, KSR prevalidation, logging,
    outputing a response and, if it passes, sending email notifying the DNSSEC
    administrator that a valid KSR has been received.

    \param fin file pointer to open incomming stream from client
    \return 0 if ok -1 if fail
*/

/*
 *  POST /nph-xxtcp.cgi HTTP/1.1
 *  Host: www.netwitness.org
 *  User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6
 *  Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*?/?*;q=0.5
 *  Accept-Language: en-us,en;q=0.5
 *  Accept-Encoding: gzip,deflate
 *  Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
 *  Keep-Alive: 300
 *  Connection: keep-alive
 *  Referer: http://www.netwitness.org/xx.cgi
 *  Content-Type: multipart/form-data; boundary=---------------200071578424558
 *  Content-Length: 4913
 *  
 *  -----------------200071578424558
 *  Content-Disposition: form-data; name="fileframe"
 *  
 *  true
 *  -----------------200071578424558
 *  Content-Disposition: form-data; name="file"; filename="keyinst.exe"
 *  Content-Type: application/x-sdlc
 *  
 *  MZ....................data...
 *  -----------------200071578424558--
 *  
 */
static int rxupload(FILE *fin,uint32_t clen)
{
  char buf[MAXPATHLEN];
  int i,j,n,c,last,tend;
  uint32_t k;
  char *p;
  int bslen;
  char bs[2048];
  char cdhdr[]="Content-Disposition: form-data;";
  char fntok[]="filename=";
  char *fname;
  FILE *fout;
  int fcnt;
  char *lfname;

  /* process each part of the multipart body */
  fcnt = -1;
  fname = NULL;
  bs[0] = 0x0D;
  bs[1] = 0x0A;
  if(fgets(&bs[2],sizeof(bs)-2,fin) == NULL) return 0;
  str_cleanup(&bs[2]);
  bslen = strlen(bs);

  if(debug > 2) printf("%s\n",&bs[2]);

  while(fgets(buf,sizeof(buf),fin)) {  /* CVTY buf tainted */

    /* section header */
    do {
      if(buf[0] == 0x0D && buf[1] == 0x0A) break;
      str_cleanup(buf);
      if(debug > 2) printf("%s\n",buf);
      if(strncasecmp(buf,cdhdr,sizeof(cdhdr)-1) == 0) {
        if((p=strstr(&buf[sizeof(cdhdr)],fntok))) {
          char *q,*q0;
          p += sizeof(fntok);
          q = q0 = p;
          for(;*p && *p != ';';p++) { if(*p != '"') *q++ = *p; }
          *q = '\0';
          if((q=strrchr(q0,'\\'))) q0 = q+1;
          else if((q=strrchr(q0,'/'))) q0 = q+1;
          fname = strdup(q0);
        }
      }
    } while(fgets(buf,sizeof(buf),fin));

    /* data */
    /*SHA256_Init(&ctx256);*/
    fcnt++;
    if(fname) {
      snprintf(buf,sizeof(buf),"%s/in/%s_%u_%s_%05u_%s_%s",basedir,progname,fcnt,nowstr,getpid(),remoteaddr,fname);
    } else {
      snprintf(buf,sizeof(buf),"%s/in/%s_%u_%s_%05u_%s_%s",basedir,progname,fcnt,nowstr,getpid(),remoteaddr,"null");
    }
    if((fout=fopen(buf,"w+")) == NULL) { /* CVTY tainted */
      logger_error("Cannot open temp file \"%s\"",buf);
    }
    lfname = strdup(buf);

    i = 0;
    n = 0;
    k = 0;
    j = 0;
    tend = 0;
    last = 0;
    while((c=fgetc(fin)) != EOF) {
      n++;
      buf[i++] = (char)c;
      /* detect boundary */
      if(tend == 1) {
        if(c == 0x0D) { if(debug > 2) printf(" %02x",c); tend = 2; continue; }
        if(c == '-') { if(debug > 2) printf("%c",c); tend = 3; continue; }
        if(debug > 2) printf("<br>\n");
        j = 0;
        tend = 0;
      }
      if(tend == 2) {
        if(c == 0x0A) {
          if(debug > 2) printf(" %02x",c);
          i -= (bslen+2); /* for <CR><LF>boundary<CR><LF> */
          if(last) i -= 2; /* for "--" */

          n -= (bslen+2);
          if(last) n -= 2;

          break;
        } else {
          if(debug > 2) printf("<br>\n");
          j = 0;
          tend = 0;
        }
      }
      if(tend == 3) {
        if(c == '-') {
          if(debug > 2) printf("%c",c);
          tend = 1;
          last = 1;
          continue;
        } else { /* wasnt a "--" so must be data */
          if(debug > 2) printf("<br>\n");
          tend = 0;
          j = 0;
        }
      }
      last = 0;
    retry:
      if(c == bs[j]) {
        if(debug > 2) printf("%c",c);
        j++;
        if(j == bslen) {
          tend = 1;
        }
        continue;
      } else if(j) {
        j = 0;
        goto retry;
      }

      if(j == 0 && i >= (int)(sizeof(buf)/2)) {
        /*SHA256_Update(&ctx256,buf,i);*/
        fwrite(buf,1,i,fout);
        k += i;
        i = 0;
      }

    }

    if(i > 0) {
      /*SHA256_Update(&ctx256,buf,i);*/
      fwrite(buf,1,i,fout);
      k += i;
    }

    /*SHA256_End(&ctx256,fingerprint);*/
    fflush(fout);
    rewind(fout);
    printf("FILE: %s<br>\n",fname?fname:"-");

    /*! xmllint added for Jakob */
    if(fname) { /* test only if real */
      snprintf(buf, sizeof(buf),
	       "%s --noout --relaxng %s/ksr.rng \"%s\" > /dev/null",
	       WKSR_XMLLINT, basedir, lfname);
      if(system(buf)) {
	logger_error("Bad XML format:|%s|%s|",buf,lfname);
	free(lfname);
	goto fend;
      }
    } else {
      fclose(fout);
      free(lfname);
      goto fend;
    }

    if(prevalidate(fout)) { /* error - leave it where it is */
      fclose(fout);
    } else { /* success - move it to be processed */
      fclose(fout);
      snprintf(buf,sizeof(buf),"%s/out/%s_%u_%s_%05u_%s_%s",basedir,progname,fcnt,nowstr,getpid(),remoteaddr,fname);
      rename(lfname,buf);
      /*myx_syslog(LOG_INFO,"New KSR in %s\n",buf);  Do not tell the world were this lives */

      snprintf(buf, sizeof(buf),
        "%s -s \"%s\" %s < %s > /dev/null 2>&1",
        WKSR_MAILX, WKSR_MAILSUBJECT, WKSR_MAILADDRESS, logger_filename());

      if(system(buf)) {
        logger_error("Trouble sending notifying email");
      }

    }
    free(lfname);

 fend:
    if(fname) {
      /*printf("%s (%d %lu bytes) witnessed at %s UTC\n",fname,n,k,now);*/
      /*rdump(buf,i);*/
      free(fname);
      fname = NULL;
    }
    
    if(last) break;
  }

  return 0;
}


/*
 *! Do basic validation of KSR w/o HSM.  Similar to ksrsigner.
\param fksr file pointer to temporary file with incomming KSR
\return 0 if ok, non-zero if KSR had errors
 */
static int prevalidate(FILE *fksr)
{
  xmlstate _xs,*xs;
  xmlstate _xss,*xss;
  int i,ret,hashlen;
  uint8_t hash[1024];
  char lbuf[MAXPATHLEN];
  FILE *fin;

  ret = -1;

  /*
   * Most Initialization done prior to this
   */
  /*
   * It is out of policy to provide signed key bundles for more that 
   * 6 months in advance and as per policy we will not sign a KSR until
   * 60 days before its cycle. 
   * However, we will except KSR submissions up to 90 days before
   * the start of the cycle.
   * We account for 31 day months and the 5 day overlap for KSR
   * submissions here.
   */
  maxexpiration = t_now + ((T_VLIMIT+6+5)*T_ONEDAY);
  DefaultTTL = T_DEFAULT_TTL;
  t_step = T_STEP*T_ONEDAY;
  validityperiod = T_VALIDITY*T_ONEDAY;

  xs = &_xs;
  memset(xs,0,sizeof(xmlstate));
  xss = &_xss;
  memset(xss,0,sizeof(xmlstate));

  /*
   * Load local copy of SKR[n-1]
   */
  ksrinvalid = 0;

  snprintf(lbuf,sizeof(lbuf),"%s/skr.xml",basedir);
  if((fin=fopen(lbuf,"r")) == NULL) {
    logger_error("Cannot open last KSR response file %s",lbuf);
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
  logger_info("Prior SKR...");
  display_reqresp(xss->rqrs,xss->rqrscnt);

  /*
   * Prospective KSK's /w no private half.
   * If this is a KSK roll, this will change.
   */ 
  {
    krecord *y;
    int j;

    for(i=0;i<xss->rqrscnt;i++) {
      for(y=xss->rqrs[i]->x_key;y;y=y->next) {
        if((y->Flags & DNSKEY_SEP_FLAG) == 0) continue;
        for(j=0;j<nksk;j++) {
          if(strcmp(y->PublicKey,ksks[j]->PublicKey) == 0) break;
        }
        if(j == nksk) {
          ksks[nksk++] = y;
          y->signer = 1;
        }
      }
    }
  }

  /* check policies of SKR */
  for(i=0;i<xss->rqrscnt;i++) {
    check_responsebundle(xss->rqrs[i]);
  }

  if(ksrinvalid) goto end;
  logger_info("...OK");
  logger_info("");

  /*
   * Validate KSR[n] and create fake response
   */
  logger_info("Pre-Validate KSR...");

  ksrinvalid = 0;

  /* parse KSR */
  xs->fin = fksr;
  xmlparse("",xs);
  rewind(fksr);
  hashlen = hashfile(fksr,HASH_SHA256,hash);

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

  if(ksrinvalid) goto end;

  /*
   * SKR[n-1]ZSK[0] == KSR[n]ZSK[-] ?
   * --> SKR[n-1]ZSK[+] == KSR[n]ZSK[0] ?
   */
  {
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
      logger_error("Problem with ZSK trust daisey chain.");
      logger_error("....FAILED. Skipped SKR-KSR trust chain check");
      ksrinvalid++;
    } else {
      logger_info("...PASSED.");
    }
    logger_info("");
  }

  /*if(ksrinvalid) goto end;*/

  /*myx_syslog(LOG_INFO,"...PASSED.\n\n");*/

  {
    mbuf *bp;
    char *p;
    int i;

    logger_info("KSR SHA256 HASH:");
    hdump(hash,hashlen);
    bp = pgp_wordlist2(hash,hashlen);
    i = 0;
    for(p=(char *)bp->p0;*p;p++) {
      myx_syslog(LOG_INFO,"%c",*p);
      i++;
      if(*p == ' ' && i > 60) {
        i = 0;
        myx_syslog(LOG_INFO,"\n");
      }
    }
    logger_info("<br>");
    mbuf_free(bp);
  }

  /*
   * Faux-Sign the KSR
   */
  snprintf(lbuf,sizeof(lbuf),"%s/tmp/%s_%s_%u_tmp_skr.xml",basedir,progname,nowstr,getpid());
  if((fin=fopen(lbuf,"w+")) == NULL) {
    logger_error("Cannot open input file %s",lbuf);
    goto end;
  }
  signem(fin,xs);

  if(ksrinvalid) {
    fclose(fin);
    goto end;
  }

  rewind(fin);
  logger_info("PROSPECTIVE KSR RESPONSE:");
  while((i=fgetc(fin)) != EOF) {
    if(i == '<') myx_syslog(LOG_INFO,"&lt;");
    else if(i == '>') myx_syslog(LOG_INFO,"&gt;");
    else myx_syslog(LOG_INFO,"%c",i);
  }
  fclose(fin);

  ret = 0;

 end:
  for(i=0;i<xss->rqrscnt;i++) free_requestresponse(xss->rqrs[i]);
  for(i=0;i<xs->rqrscnt;i++) free_requestresponse(xs->rqrs[i]);

  return ret;
}


/******************************************************************
 * RRSIG function
 ******************************************************************/

/*! Compare function for qsort to put keys in order for rrsig function below

    \param a
    \param b
    \return 1 if (a) key data > (b) keydata; -1 if < and 0 if equal 
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
    t_expiration. If shiwkeys is initially set, routine will writw keys to
    ftmp as well as sigs. Note: validateable keybundles are written into tmp
    to simplify final valisation.

    This is non-HSM dependant version for web based prevalidation.

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
  FILE *fkeyb;

  /* 
   * To test RRSIG just created:
   *   dnssec-signzone -v 10 -o . skr.keybundle
   * Output should indicate our KSK RRSIGs were "retained"
   */
  snprintf((char *)hash,sizeof(hash),skr_keybundle_template,testitbcnt++);
  if((fkeyb=fopen((char *)hash,"w+"))) {
    fprintf(fkeyb,"; To test RRSIG s  we have created:\n;   dnssec-signzone -v 10 -o %s %s\n; Output should indicate our KSK RRSIGs were \"retained\"\n",dn,hash);
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
      logger_error("%s Currently algorithm %d is not supported\n",__func__,dr->Algorithm);
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

    if(fkeyb) fprintf(fkeyb,"NOHSM\n");
    fprintf(ftmp,"NOHSM");

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

    Validate the keybundle made up of keys in klist and signatures in s.
    returns 0 if validation successful. HSM path has no reliance on external
    routines like OPENSSL. If no HSM, OPENSSL is used. This is true for the
    Web based pre-acceptance testing on KSRs

    This is non-HSM version and does not truly validate SKR since there is no
    private key access. (i.e., this can be spoofed). But it is a good
    prevalidation step.

    \param s Signature created by one of the key in klist
    \param klist List of krecord structures.
    \return 0
 */
#include <openssl/bn.h>

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
    logger_error("in %s.  No key in bundle matching signature %s\n",s->keyIdentifier);
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
       * RR(i) = owner | type | class | TTL | RDATA length | RDATA
       * owner = canonical
       * type(16) A = 1, DNSKEY = 48 RRSIG = 46  all Network Order
       * class(16) IN = 1
       * ttl (32)
       * RDATA length(16)
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
        *(uint16_t *)w = htons(dr->Flags); w += 2; /* flags */
        *(uint8_t *)w = dr->Protocol; w++; /* proto */
        *(uint8_t *)w = dr->Algorithm; w++; /* alg */
        n = base64decode(dr->PublicKey,w,sizeof(wire)); w += n; /* public key */
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
      logger_error("%s Currently algorithm %d is not supported\n",__func__,s->Algorithm);
      return -1;
    }

    gh.type = htype;
    hashit(&gh,NULL,0);
    w = wire;
    *(uint16_t *)w = htons(48); w += 2; /* type = DNSKEY */
    *(uint8_t *)w = s->Algorithm; w += 1;  /* alg = 5 RSASHA1 */
    *(uint8_t *)w = s->Labels; w += 1;  /* label = 1 */
    *(uint32_t *)w = htonl(s->OriginalTTL); w += 4; /* ttl */
    *(uint32_t *)w = htonl(s->SignatureExpiration); w += 4; /* exp */
    *(uint32_t *)w = htonl(s->SignatureInception); w += 4; /* incep */
    *(uint16_t *)w = htons(s->KeyTag); w += 2; /* tag - here /w KSK flag */
    n = dnssec_dn2wire(s->SignersName,w); w += n; /* dn0 */
    n = (int)(w-wire);

    hashit(&gh,wire,n);

    for(n=0;n<keycnt;n++) {
      wirerr *rr;
      rr = (wirerr *)keys[n]->user;
      hashit(&gh,rr->w,rr->len);
    }

    if((hashlen=hashit(&gh,hash,0)) < 0) {
      logger_error("%s hash computation failed\n",__func__);
      return -1;
    }
  }

  {
    BN_CTX *ctx;
    BIGNUM *rs,*rsa_n,*rsa_e,*rsa_c;
    uint8_t *q;
    int n,i;
    uint8_t usig[1024]; /* 128 bytes for 1024bit key */
    int usiglen;

    ctx = BN_CTX_new();

    n =  base64decode(sk->PublicKey,usig,sizeof(usig));
    q = usig;
    /* if usig[0] == 0 then len = (uint16_t *)&usig[1]
       else len = usig[0] */
    if(*q) {
      i = *q++;
      n -= (i+1);
    } else {
      i = *(uint16_t *)(q+1);
      q += 3;
      n -= (i+3);
    }
    /* n = modulus length / 8 */
    rsa_e = BN_bin2bn(q,i,NULL); /* exponent */
    q += i;
    rsa_n = BN_bin2bn(q,n,NULL); /* modulus */

    n =  base64decode(s->SignatureData,usig,sizeof(usig));
    rsa_c = BN_bin2bn(usig,n,NULL); /* */

    rs = BN_new();
    if(BN_mod_exp(rs,rsa_c,rsa_e,rsa_n,ctx) != 1) {
      logger_error("Failed modulo-exponent function for |%s|\n",sk->keyIdentifier);
      ksrinvalid++;
      return -1;
    }
    memset(usig,0,sizeof(usig));
    /*BN_print_fp(stdout,&rs);*/
    n = BN_bn2bin(rs,&usig[1]);
    n++; /* account for leading 0x00 */
    usiglen = n;

    BN_free(rsa_c);
    BN_free(rsa_e);
    BN_free(rsa_n);
    BN_free(rs);
    BN_CTX_free(ctx);

    /* Just compare HASH at end of DER encoding */
    if(usiglen < hashlen || memcmp(&usig[usiglen-hashlen],hash,hashlen))
      ret = -1;
    else 
      ret = 0;
  }

  if(ret) {
    logger_error("Cannot validate private key ownership for keyIdentifier |%s|",sk->keyIdentifier);
#ifdef KEEPTRY
    ret = 0;
#else
    ksrinvalid++;
#endif
  }
  return ret;
}

/*! Misc PKCS11 support functions for this non-HSM and non-PKCS11 web based
    validator.
 */

/*! Check if corresponding private key available. Always no for this non-HSM
    case.

    \param vkr pkcs11 key block
    \return 0  No-private key.
 */
int pkcs11_have_private_key(void *vkr)
{
  return 0; /* non-HSM so no private key */
}

/*! Empty pkcs11 key block free routine to satisfy common code between
    ksrsigner and wksr

    \param vkr pkcs11 key block
 */
void pkcs11_free_pkkeycb(void *vkr)
{
  /* arg should always be null */
}
