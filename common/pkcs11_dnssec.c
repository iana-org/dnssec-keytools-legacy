/*
 * $Id: pkcs11_dnssec.c 578 2011-09-13 23:24:41Z lamb $
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

#include "config.h"

#include "util.h"
#include <dirent.h>
#include <dlfcn.h>
#include "logger.h"
#include "mbuf.h"
#include "cryptoki.h"
#include "pkcs11_dnssec.h"
#include "base32.h"

/*! malloc wrapper to exit on allocation failure

    \param n number of bytes to allocate
    \return char pointer to allocated buffer
 */
static char *pkcs11_malloc(int n)
{
  char *p;

  if((p=malloc(n)) == NULL) {
    logger_fatal("pkcs11: Can not malloc(%d) memory in %s",n,__func__);
  }
  return p;
}

/*! calloc wrapper to exit on allocation failure.

    \param n number of elements to allocate
    \param j size of elements to allocate
    \return char pointer to allocated zeroed buffer
 */
static char *pkcs11_calloc(int n,int j)
{
  char *p;

  if((p=calloc(n,j)) == NULL) {
    logger_fatal("pkcs11: Can not malloc(%d) memory in %s",n,__func__);
  }
  return p;
}

/*! return key bit length

    \param vkr void cast pointer to pkcs11 key stuct for key in question
    \return -1 if error or key bit length
*/
int pkcs11_bits(void *vkr)
{
  if(vkr == NULL) {
    logger_error("pkcs11: NULL argument to %s",__func__);
    return -1;
  }
  return ((pkkeycb *)vkr)->bits;
}

/*! return mbuf with key modulus

    \param vkr void cast pointer to pkcs11 key stuct for key in question
    \return NULL if error or pointer to mbuf with modulus
*/
mbuf *pkcs11_modulus(void *vkr)
{
  if(vkr == NULL) {
    logger_error("pkcs11: NULL argument to %s",__func__);
    return NULL;
  }
  return ((pkkeycb *)vkr)->modulus;
}

/*! return mbuf with public key exponent

    \param vkr void cast pointer to pkcs11 key stuct for key in question
    \return NULL if error or pointer to mbuf with public exponent
*/
mbuf *pkcs11_pubexp(void *vkr)
{
  if(vkr == NULL) {
    logger_error("pkcs11: NULL argument to %s",__func__);
    return NULL;
  }
  return ((pkkeycb *)vkr)->pubexp;
}

/*! return mbuf for CKA_LABEL for vkr key 

    \param vkr void cast pointer to pkcs11 key stuct for key in question
    \return NULL if error or pointer to mbuf with CKA_LABEL
 */
mbuf *pkcs11_label(void *vkr)
{
  if(vkr == NULL) {
    logger_error("pkcs11: NULL argument to %s",__func__);
    return NULL;
  }
  return ((pkkeycb *)vkr)->label;
}

/*! check to see if we have access to the private key in this key strust

    \param vkr void cast pointer to pkcs11 key struct for key in question
    \return 1 if have private key; 0 if not
 */
int pkcs11_have_private_key(void *vkr)
{
  if( ((pkkeycb *)vkr)->hkp ) return 1;
  return 0;
}

/*! free pkcs11 key struct

    \param vkr void cast pointer to pkcs11 key struct to free
 */
void pkcs11_free_pkkeycb(void *vkr)
{
  pkkeycb *pk;

  if(vkr == NULL) {
    return;
  }
  pk = (pkkeycb *)vkr;
  if(pk->pubexp) mbuf_free(pk->pubexp);
  if(pk->modulus) mbuf_free(pk->modulus);
  if(pk->label) mbuf_free(pk->label);
  if(pk->id) mbuf_free(pk->id);
}

static CK_BBOOL ctrue = CK_TRUE;
static CK_BBOOL cfalse = CK_FALSE;

static char *pkcs11_ret_str(CK_RV rv);

#define LBUFLEN MAXPATHLEN
#define NARGS 50

static pkcs11cb pklist[PKCS11_MAX_SLOTS];
static int pklistcnt;
static int pkcs11init;

static char *current_hsmconfig=NULL;

/*! read fname and set environment variables for this process accordingly.

    input: fname file /w env vars. e.g.
      KEYPER_LIBRARY_PATH=$HOME/dnssec/ksr/AEP
      LD_LIBRARY_PATH=$KEYPER_LIBRARY_PATH
      PKCS11_LIBRARY_PATH=$KEYPER_LIBRARY_PATH/pkcs11.GCC4.0.2.so.4.07
    
    output: nothing
    return: 0 success, else failed

    \param fname name of HSM configuration file (e.g., aep.hsmconfig) to open
    \return -1 if failed; 0 if success
 */
static int setenvvars(char *fname)
{
  FILE *fp;
  char lbuf[LBUFLEN];

  if(fname == NULL) return -1;
  if((fp=fopen(fname,"r")) == NULL) return -1;
  /*myx_syslog(LOG_INFO,"Using hsmconfig %s\n",fname);*/
  while(fgets(lbuf,sizeof(lbuf),fp)) {
    int n;
    char *args[NARGS];
    
    if(lbuf[0] == '#') continue;
    n = lparse(lbuf,args,NARGS,'=');
    if(n < 1) continue;
    if(n == 1) {
     if(unsetenv(args[0])) {
       logger_message(LOG_ERR, 
         "Failed to clear environment variable %s (errno=%d, %s)",
         args[0], errno, strerror(errno));
       return -1;
     } else {
       logger_message(LOG_DEBUG, "unsetenv %s", args[0]);      
     }
    } else { /* fully expand the RHS before assigning */
      char obuf[2048],*p,*q,*ev,c,*r;
      q = obuf;
      p = args[1];
      ev = NULL;
      while(*p) {
        if(ev) {
          if(*p == '|' || *p == '&' || *p == ':' || *p == ';' || *p == ' ' || *p == '\t' || *p == '/' || *p == '\\' || *p == '(' || *p == ')' || *p == '<' || *p == '>' || *(p+1) == '\0') {
            
            if(*(p+1) == '\0') p++;
            
            c = *p;
            *p = '\0';
            if((r=getenv(ev))) {
              while(*r) *q++ = *r++;
              *q++ = c;
            } else {
              /*myx_syslog(LOG_INFO,"Could not get environment variable \"%s\"\n",ev); may be NULL */
            }
            ev = NULL;
          } else {
          }
        } else {
          if(*p == '$') ev = p+1;
          else *q++ = *p;
        }
        p++;
      }
      *q++ = '\0';
      /*printf("%s=%s\n",args[0],obuf); */
      if(setenv(args[0],obuf,1)) {
        logger_message(LOG_ERR, 
          "Failed to set environment variable %s (errno=%d, %s)",
          args[0], errno, strerror(errno));
        return -1;
      } else {
        logger_message(LOG_DEBUG, "setenv %s=%s", args[0], obuf);
      }
    }
  }
  fclose(fp);
  return 0;
}

/*! check and set previously verified environment variables.

    Important when dealing with multiple HSMs from different vendors.

    \param pk pointer to pkcs11 HSM slot structure
*/
static void checkandsetenv(pkcs11cb *pk)
{
  if(pk->hsmconfig &&
     (current_hsmconfig == NULL || strcmp(current_hsmconfig,pk->hsmconfig))) {
    setenvvars(pk->hsmconfig);
    current_hsmconfig = pk->hsmconfig;
  }
}

/*! HSM subsystem initialization routine

    Learns and draws in as much information about the HSM(s) and slots as
    possible.

    \param otherdir If non-null then path to other directory to scan for HSM configuration files in addition to the current directory.  config files in current directory take precedence.
    \return -1 if error; 0 if success.
 */
int pkcs11_init(char *otherdir)
{
  char *p,fname[MAXPATHLEN];
  DIR *dirp;
  struct dirent *dp;
  char *scandir,*lib;
  pkcs11cb *pk;
  int i;

  if(pkcs11init) return 0;

  scandir = ".";

 redirscan:
  if((dirp = opendir(scandir)) == (DIR *)0) {
    logger_error("pkcs11: Cannot open %s directory",scandir);
    return -1;
  }

  while((dp = readdir(dirp))) {

    if(strcmp(dp->d_name,".") == 0 || strcmp(dp->d_name,"..") == 0)
      continue;

    if((p=strrchr(dp->d_name,'.')) == NULL) continue;
    if(strcmp(p,".hsmconfig")) continue;

    snprintf(fname,sizeof(fname),"%s/%s",scandir,dp->d_name);
    for(i=0;i<pklistcnt;i++) {
      if(pklist[i].hsmconfig && strcmp(pklist[i].hsmconfig,fname) == 0) break;
    }

    if(i == pklistcnt) {
      char buf[80];

      logger_info("Use HSM %s?", fname);
      printf("Activate HSM prior to accepting in the affirmative!! (y/N): ");

      if(fgets(buf,sizeof(buf),stdin) == NULL) {
        printf("\n");
        logger_info("HSM %s NOT activated.", fname);        
        continue;
      } else {
        printf("\n");
      }
      
      if(buf[0] != 'y' && buf[0] != 'Y') {
        logger_info("HSM %s NOT activated.", fname);        
        continue;
      }
    }
    
    logger_info("HSM %s activated.", fname);

    if(setenvvars(fname)) {
      logger_warning("pkcs11: %s Can't process %s",__func__,fname);
      continue;
    }
    if((lib=getenv("PKCS11_LIBRARY_PATH")) == NULL) { /* CVTY FIXME tainted */
      logger_error("You must set at least PKCS11_LIBRARY_PATH");
      continue;
    }

    for(i=0;i<pklistcnt;i++) {
      if(strcmp(pklist[i].lib,lib) == 0) break;
    }
    if(i == pklistcnt) {
      CK_C_GetFunctionList   pGFL;
      void                  *hLib;
      CK_FUNCTION_LIST_PTR   pfl;
      CK_SESSION_HANDLE      sh;
      CK_ULONG               nslots=PKCS11_MAX_SLOTS;
      CK_SLOT_ID             SlotList[PKCS11_MAX_SLOTS];
      int rv,k;

      hLib = dlopen(lib,RTLD_LAZY); /* CVTY FIXME tainted */
      if(!hLib) {
        logger_error("Failed to open PKCS11 library %s: %s",lib,dlerror());
        continue;
      }
      if((pGFL=(CK_C_GetFunctionList)dlsym(hLib,"C_GetFunctionList")) == NULL) {
        logger_error("pkcs11: Cannot find GetFunctionList()");
        dlclose(hLib);
        continue;
      }
      if((rv=pGFL(&pfl)) != CKR_OK) {
        logger_error("pkcs11: C_GetFunctionList: %s",pkcs11_ret_str(rv));
        dlclose(hLib);
        continue;
      }
      if((rv=pfl->C_Initialize(NULL)) != CKR_OK) {
        logger_error("pkcs11: C_Initialize: %s",pkcs11_ret_str(rv));
        dlclose(hLib);
        continue;
      }
      /*
       * could do this as a sub structure but we wont have that 
       * many HSM's and slots to manage, so keep it short and simple.
       */
      if((rv=pfl->C_GetSlotList(CK_TRUE,SlotList,&nslots)) != CKR_OK) {
        logger_error("pkcs11: C_GetSlotList: %s",pkcs11_ret_str(rv));
        dlclose(hLib);
        continue;
      }
      if(nslots <= 0) {
        logger_error("No available slots");
        dlclose(hLib);
        continue;
      }
      logger_info("Found %d slots on HSM %s",nslots,lib);
      for(k=0;k<(int)nslots;k++) {

        if(nslots > 1) {
          char buf[80];

          printf("Include HSM slot %d ? (Y/n): ", k);

          if(fgets(buf,sizeof(buf),stdin) == NULL) {
            printf("\n");
            logger_info("HSM slot %d NOT included", k);            
            continue;
          } else {
            printf("\n");            
          }

          if(buf[0] == 'n' || buf[0] == 'N') {
            logger_info("HSM slot %d NOT included", k);            
            continue;
          }
        } else {
          /* just accept it */
        }

        logger_info("HSM slot %d included", k);

        if((rv=pfl->C_OpenSession(SlotList[k],CKF_RW_SESSION | CKF_SERIAL_SESSION,NULL,NULL,&sh)) != CKR_OK) {
          logger_error("pkcs11: C_OpenSession: %s",pkcs11_ret_str(rv));
          continue;
        }
        pk = &pklist[pklistcnt];
        pk->hsmconfig = strdup(fname);
	current_hsmconfig = pk->hsmconfig; /* keep track of current env */
        pk->lib = strdup(lib);
        pk->hLib = hLib;
        pk->pfl = pfl;
        pk->slot = k;
        pk->sh = sh;
        pk->pin = PKCS11_DEFAULT_PIN;
        pklistcnt++;
        logger_info("Loaded %s Slot=%d",pk->lib,pk->slot);
        {
          CK_TOKEN_INFO token_info;

          logger_info("HSM Information:");
          memset(&token_info,0,sizeof(CK_TOKEN_INFO));
          if(pfl->C_GetTokenInfo(SlotList[k],&token_info) == CKR_OK) {
            token_info.label[sizeof(token_info.label) - 1] = '\0';
            token_info.manufacturerID[sizeof(token_info.manufacturerID) - 1] = '\0';
            token_info.model[sizeof(token_info.model) - 1] = '\0';
            token_info.serialNumber[sizeof(token_info.serialNumber) - 1] = '\0';
            logger_info("    Label:           %s",token_info.label);
            logger_info("    ManufacturerID:  %s",token_info.manufacturerID);
            logger_info("    Model:           %s",token_info.model);
            logger_info("    Serial:          %s",token_info.serialNumber);
          }
          logger_info("");
        }

      }
    }
  }
  closedir(dirp);
  if(pklistcnt == 0 && otherdir) {
    scandir = otherdir;
    otherdir = NULL;
    goto redirscan;
  }
  if(pklistcnt <= 0) {
    logger_error("Could not load any HSMs");
    return -1;
  }
  pkcs11init = 1;
  return 0;
}

/*! close PKCS11 library

    if vpk is NULL, all HSMs are closed. Otherwise only the HSM specified by
    vpk is closed.

    \param vpk void cast pointer to pkcs11 key struct to close.  If NULL, close all.
*/
void pkcs11_close(void *vpk)
{
  pkcs11cb *pk2;
  int cnt,i,k,rv;
  CK_SESSION_HANDLE      sh;
  CK_FUNCTION_LIST_PTR pfl;

  if(pkcs11init == 0) return;

  for(k=0;k<pklistcnt;k++) {

    pk2 = &pklist[k];
    if(vpk && pk2 != (pkcs11cb *)vpk) continue;
    if(pk2->hLib == NULL) continue;

    checkandsetenv(pk2);
    pfl = pk2->pfl;
    sh = pk2->sh;
    if(pk2->loggedin) {
      if((rv=pfl->C_Logout(sh)) != CKR_OK) {
        logger_error("pkcs11: %s C_Logout: %s",__func__,pkcs11_ret_str(rv));
      }
    }
    if((rv=pfl->C_CloseSession(sh)) != CKR_OK) {
      logger_error("pkcs11: %s C_CloseSession: %s",__func__,pkcs11_ret_str(rv));
    }

    cnt = 0;
    for(i=0;i<pklistcnt;i++) {
      if(pklist[i].hLib == pk2->hLib) cnt++;
    }
    if(cnt == 1) { /*!< only un-load lib on last one */
      if((rv=pfl->C_Finalize(NULL)) != CKR_OK) {
        logger_error("pkcs11: %s C_Finalize: %s",__func__,pkcs11_ret_str(rv));
      }
      dlclose(pk2->hLib);
    }

    logger_info("Unloaded %s Slot=%d",pk2->lib,pk2->slot);
    
    free(pk2->hsmconfig);
    free(pk2->lib);
    memset(pk2,0,sizeof(pkcs11cb));
  }
  for(i=0;i<pklistcnt;i++) if(pklist[i].hsmconfig) break;
  if(i == pklistcnt) pkcs11init = 0;
}

/*! log in to HSM slot referrenced by pk
    \param pk pointer to HSM slot struct to log in to
    \return -1 if failed; 0 if success
 */
static int pkcs11_login(pkcs11cb *pk)
{
  int rv;
  CK_SESSION_HANDLE      sh;
  CK_FUNCTION_LIST_PTR pfl;

  if(pk->pfl == NULL || pk->sh == 0) {
    logger_error("Can't login in to slot %u on HSM %s. Slot not open.",pk->slot,pk->hsmconfig);
    return -1; /* not open */
  }
  checkandsetenv(pk);
  if(pk->loggedin) return 0; /* already logged in */
  pfl = pk->pfl;
  sh = pk->sh;

  /*
   * From pkcs11_dnssec.h:
   *   pk->pin
   *     null:no login needed
   *     nonnull+zerolen:interactive pin
   *     nonzero len:has pin in it
   */
  if(pk->pin) { /* needs login */
    if(strlen(pk->pin) == 0) { /* has a buffer but no PIN */
      char buf[80];
      int i;

      while(1) {
        printf("Please enter PIN for slot %d: ",pk->slot);
        if(fgets(buf,sizeof(buf),stdin)) {
          printf("\n");
          buf[sizeof(buf) - 1] = '\0';
          i = strlen(buf) - 1;
          buf[i] = '\0';
          logger_info("PIN input accepted");
        } else {
          printf("\n");
          logger_error("PIN input error");
          return -1;
        }        
        
        if((rv=pfl->C_Login(sh,CKU_USER,(unsigned char *)buf,i)) != CKR_OK) {
          logger_error("pkcs11: C_Login: %s",pkcs11_ret_str(rv));
        } else {
          break;
        }
      }
    } else { /* buffer has PIN in it */
      if((rv = pfl->C_Login(sh,CKU_USER,(unsigned char *)pk->pin,strlen(pk->pin))) != CKR_OK) {
        logger_error("pkcs11: C_Login: %s",pkcs11_ret_str(rv));

        return -1;
      }
    }
  }

  pk->loggedin = 1;

  return 0;
}

#if 0
/* log out of HSM slot referrenced by pk
   \param pk pointer to HSM slot struct
   \return 0
*/
static int pkcs11_logout(pkcs11cb *pk)
{
  int rv;
  CK_SESSION_HANDLE sh;
  CK_FUNCTION_LIST_PTR pfl;

  checkandsetenv(pk);
  sh = pk->sh;
  pfl = pk->pfl;
  if(pfl == NULL || sh == 0) return -1; /* not open */
  if(pk->loggedin) { /* needed login */
    if((rv=pfl->C_Logout(sh)) != CKR_OK) {
      myx_syslog(LOG_ERR,"error: C_Logout: %s\n",pkcs11_ret_str(rv));
    }
  }
  pk->loggedin = 0;
  return 0;
}
#endif /* 0 */

#if 0
/*
\return the size of the pkcs11 control block
 */
int pkcs11_cbsize()
{
  return sizeof(pkcs11cb);
}
#endif /* 0 */

/*! Verify the signature in "sig/siglen" over "data/datalen" with 
    public key described by modulus and pubexp using PKCS11 calls.
    Returns 0 if successful.

    \param modulus mbuf containing key modulus
    \param pubexp mbuf containing key public exponent
    \param sig pointer to buffer containing signature of data
    \param siglen length of signature
    \param data pointer to buffer containing data
    \param datalen length of data
    \return -1 if failed; 0 if validated
 */
int pkcs11_hsmverify(mbuf *modulus,mbuf *pubexp,uint8_t *sig,int siglen,uint8_t *data,int datalen)
{
  CK_FUNCTION_LIST_PTR  pfl;
  CK_RV                 rv;
  CK_SESSION_HANDLE     sh;
  CK_OBJECT_HANDLE      hKey;
  CK_MECHANISM mechanism;
  CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_ATTRIBUTE template[] = {
    {CKA_CLASS, &class, sizeof (class) },
    {CKA_KEY_TYPE, &keyType, sizeof (keyType) },
    {CKA_MODULUS, NULL, 0},
    {CKA_PUBLIC_EXPONENT, NULL, 0},
    {CKA_VERIFY, &ctrue, sizeof (ctrue) },
  };

  if(modulus == NULL || pubexp == NULL || sig == NULL || data == NULL || siglen <= 0 || datalen <= 0) {
    logger_error("pkcs11: NULL argument to %s",__func__);
    return -1;
  }
  /* just use the first HSM available */
  if(pklist[0].pfl == NULL) {
    logger_error("pkcs11: No initialized HSM slots in %s",__func__);
    return -1;
  }
  checkandsetenv(&pklist[0]);
  pfl = pklist[0].pfl;
  sh = pklist[0].sh;

  template[2].ulValueLen = (int)(modulus->pc - modulus->p0);
  template[2].pValue = modulus->p0;

  template[3].ulValueLen = (int)(pubexp->pc - pubexp->p0);
  template[3].pValue = pubexp->p0;
  
  hKey = (CK_OBJECT_HANDLE)NULL;
  if((rv=pfl->C_CreateObject(sh,template,sizeof(template)/sizeof(CK_ATTRIBUTE),&hKey)) != CKR_OK) {
    logger_error("pkcs11: C_CreateObject: %s",pkcs11_ret_str(rv));
    return -1;
  }

  mechanism.mechanism = CKM_RSA_X_509; /* = Raw.  NOT CKM_RSA_PKCS;*/
  mechanism.pParameter = NULL_PTR;
  mechanism.ulParameterLen = 0;
  if((rv=pfl->C_VerifyInit(sh,&mechanism,hKey)) != CKR_OK) {
    logger_error("pkcs11: C_VerifyInit: %s",pkcs11_ret_str(rv));
    if((rv=pfl->C_DestroyObject(sh,hKey)) != CKR_OK) {
      logger_error("pkcs11: C_DestroyObject: %s",pkcs11_ret_str(rv));
    }
    return -1;
  }
  if((rv=pfl->C_Verify(sh,(CK_BYTE_PTR)data,(CK_ULONG)datalen,(CK_BYTE_PTR)sig,(CK_ULONG)siglen)) != CKR_OK) {
    logger_error("pkcs11: C_Verify: %s",pkcs11_ret_str(rv));
    if((rv=pfl->C_DestroyObject(sh,hKey)) != CKR_OK) {
      logger_error("pkcs11: C_DestroyObject: %s",pkcs11_ret_str(rv));
    }
    return -1;
  }

  if((rv=pfl->C_DestroyObject(sh,hKey)) != CKR_OK) {
    logger_error("pkcs11: C_DestroyObject: %s",pkcs11_ret_str(rv));
  }

  return 0;
}

/*! find public key

    Scans ALL HSM's found in pkcs11_init() for a key matching 
    non-NULL "label,id,mod,exp" and fills up to "kmax" elements 
    in "dc[]" with fresh structures including private key handles.
    
    Note: assumes "id" is ASCIIZ.

    \param label NULL or ASCIIZ CKA_LABEL to search for
    \param id NULL or ASCIIZ CKA_ID to search for
    \param mod NULL or mbuf with modulus to search for
    \param exp NULL or mbuf with public exponent to search for
    \param vdc array of kmax void cast pkcs11 key pointers to fill in 
    \param kmax size of vdc pointer array
    \return -1 on error; number of vdc elements filled in if success
 */
int pkcs11_getpub(char *label,char *id,mbuf *mod,mbuf *exp,void *vdc[],int kmax)
{
  int m,kcnt;
  CK_RV rv;
  CK_ULONG n,ts,i,k;
  pkcs11cb *pk;
  CK_FUNCTION_LIST_PTR pfl;
  CK_SESSION_HANDLE sh;
  CK_OBJECT_CLASS  class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS  privClass = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE     template[5];
  CK_OBJECT_HANDLE hk,hKeys[PKCS11_MAX_KEYS_PER_SLOT];
  CK_ATTRIBUTE     getattributes[] = {
    {CKA_MODULUS,NULL_PTR,0},
    {CKA_PUBLIC_EXPONENT,NULL_PTR,0},
    {CKA_KEY_TYPE,NULL_PTR,0},
    {CKA_LABEL,NULL_PTR,0},
    {CKA_ID,NULL_PTR,0},
  };

  if(kmax < 1 || vdc == NULL) {
    logger_error("pkcs11: invalid argument to %s",__func__);
    return -1;
  }
  kcnt = 0;
  for(m=0;m<pklistcnt;m++) {
    pk = &pklist[m];
    checkandsetenv(pk);
    pfl = pk->pfl;
    sh = pk->sh;

    pkcs11_login(pk);

    n = 0;
    template[n].type = CKA_CLASS;
    template[n].pValue = &class;
    template[n].ulValueLen = sizeof(class);
    n++;
    if(label) {
      template[n].type = CKA_LABEL;
      template[n].pValue = label;
      template[n].ulValueLen = strlen(label);
      n++;
    }
    if(id) {
      template[n].type = CKA_ID;
      template[n].pValue = id;
      template[n].ulValueLen = strlen(id);
      n++;
    }
    if(mod) {
      template[n].type = CKA_MODULUS;
      template[n].pValue = mod->p0;
      template[n].ulValueLen = (int)(mod->pc - mod->p0);
      n++;
    }
    if(exp) {
      template[n].type = CKA_PUBLIC_EXPONENT;
      template[n].pValue = exp->p0;
      template[n].ulValueLen = (int)(exp->pc - exp->p0);
      n++;
    }
    if((rv=pfl->C_FindObjectsInit(sh,template,n))!= CKR_OK) {
      logger_error("pkcs11: %s",__func__,pkcs11_ret_str(rv));
      return -1;
    }
    n = 0;
    if((rv=pfl->C_FindObjects(sh,hKeys,PKCS11_MAX_KEYS_PER_SLOT,&n)) != CKR_OK) return -1;
    if((rv=pfl->C_FindObjectsFinal(sh)) != CKR_OK) return -1;
    if(n <= 0) {
      logger_warning("No public keys meeting criteria found in HSM %s slot %d",pk->lib,pk->slot);
      continue;
    }

    for(k=0;k<n;k++) {
      hk = hKeys[k];

      ts = sizeof(getattributes)/sizeof(CK_ATTRIBUTE);
      if((rv=pfl->C_GetAttributeValue(sh,hk,getattributes,ts)) != CKR_OK) {
        logger_error("pkcs11: C_GetAttributeValue: %s",pkcs11_ret_str(rv));
        return -1;
      }
      for(i=0;i<ts;i++) {
        getattributes[i].pValue = pkcs11_malloc(getattributes[i].ulValueLen); 
      }
      if((rv=pfl->C_GetAttributeValue(sh,hk,getattributes,ts)) != CKR_OK) {
        logger_error("pkcs11: C_GetAttributeValue: %s",pkcs11_ret_str(rv));
        for(i=0;i<ts;i++) free(getattributes[i].pValue);
        return -1;
      }
      if(*(CK_KEY_TYPE *)getattributes[2].pValue != CKK_RSA) {
        logger_error("pkcs11: in %s. Unsupported key type.",__func__);
        for(i=0;i<ts;i++) free(getattributes[i].pValue);
        return -1;
      }

      if(kcnt < kmax) {
        mbuf *bp;
        pkkeycb *kr;

        kr = (pkkeycb *)pkcs11_calloc(1,sizeof(pkkeycb));

        bp = alloc_mbuf(getattributes[0].ulValueLen);
        memcpy(bp->p0,getattributes[0].pValue,getattributes[0].ulValueLen);
        bp->pc = bp->p0 + getattributes[0].ulValueLen;
        kr->modulus = bp;
        
        kr->bits = getattributes[0].ulValueLen * 8;
      
        bp = alloc_mbuf(getattributes[1].ulValueLen);
        memcpy(bp->p0,getattributes[1].pValue,getattributes[1].ulValueLen);
        bp->pc = bp->p0 + getattributes[1].ulValueLen;
        kr->pubexp = bp;

        bp = alloc_mbuf(getattributes[3].ulValueLen + 1); /* ASCIIZ */
        memcpy(bp->p0,getattributes[3].pValue,getattributes[3].ulValueLen);
        bp->pc = bp->p0 + getattributes[3].ulValueLen;
        kr->label = bp;

        bp = alloc_mbuf(getattributes[4].ulValueLen + 1); /* ASCIIZ */
        memcpy(bp->p0,getattributes[4].pValue,getattributes[4].ulValueLen);
        bp->pc = bp->p0 + getattributes[4].ulValueLen;
        kr->id = bp;

        kr->pk = (void *)pk;
        kr->hk = (void *)hk;

        /* fillinkinfo(kr); was for CKA_LABEL = DNSSEC keytag */

        /* get correspoding private key if possible */
        {
          CK_OBJECT_HANDLE hPrivKeys[2];

          i = 0;
          template[i].type = CKA_CLASS;
          template[i].pValue = &privClass;
          template[i].ulValueLen = sizeof(class);
          i++;
          template[i].type = CKA_MODULUS;
          template[i].pValue = kr->modulus->p0;
          template[i].ulValueLen = (int)(kr->modulus->pc - kr->modulus->p0);
          i++;
          template[i].type = CKA_PUBLIC_EXPONENT;
          template[i].pValue = kr->pubexp->p0;
          template[i].ulValueLen = (int)(kr->pubexp->pc - kr->pubexp->p0);
          i++;
          if((rv=pfl->C_FindObjectsInit(sh,template,i))!= CKR_OK) goto nopriv;
          i = 0;
          if((rv=pfl->C_FindObjects(sh,hPrivKeys,1,(CK_RV *)&i)) != CKR_OK) goto nopriv;
          if((rv=pfl->C_FindObjectsFinal(sh)) != CKR_OK) goto nopriv;
          if(i <= 0) {
          nopriv:
            logger_warning("No matching private key for %s in HSM %s slot %d",kr->label->p0,pk->lib,pk->slot);
          } else {
            kr->hkp = (void *)hPrivKeys[0];
          }
        }

        vdc[kcnt++] = (void *)kr;

      } else {
        logger_error("pkcs11: error in %s. More matching keys than array size. Skipping CKA_LABEL %s",__func__,getattributes[3].pValue);
        k = n;
      }
      for(i=0;i<ts;i++) {
        free(getattributes[i].pValue);
        getattributes[i].pValue = NULL;
        getattributes[i].ulValueLen = 0;
      }
    }
  }
  return kcnt;
}

/*! Raw (CKM_RSA_X_509) sign the contents of "data/datalen" with 
    the private key hkp in "kr" returning the result in sout/slen.
    Return 0 if success.

    \param vkr void casted pointer to key struct to be used for signing
    \param data pointer to data to be signed
    \param datalen length of data
    \param sout pointer to output buffer for signed result
    \param slen on call:pointer to int containing length of output buffer
                on return:int is filled in with length of result
    \return -1 if error; 0 if success
 */
int pkcs11_rsasignit2(void *vkr,uint8_t *data,int datalen,uint8_t *sout,int *slen)
{
  pkkeycb *kr;
  pkcs11cb *pk;
  CK_RV                 rv;
  CK_SESSION_HANDLE     sh;
  CK_FUNCTION_LIST_PTR  pfl;
  CK_OBJECT_HANDLE      hPriv;
  CK_MECHANISM smech;
  CK_ULONG slen2;  /* On Mac OS X we must be careful about int/CK_ULONG conversion */

  if(vkr == NULL || data == NULL || datalen <= 0 || sout == NULL || *slen <= 0) {
    logger_error("pkcs11: NULL argument to %s",__func__);
    return -1;
  }
  kr = (pkkeycb *)vkr;
  pk = (pkcs11cb *)kr->pk;
  if(pk == NULL) {
    logger_error("pkcs11: PKCS11 library not initialized");
    return -1;
  }
  checkandsetenv(pk);
  sh = pk->sh;
  pfl = pk->pfl;
  hPriv = (CK_OBJECT_HANDLE)kr->hkp;

  smech.mechanism = CKM_RSA_X_509;  /*CKM_RSA_PKCS;*/
  smech.pParameter = NULL_PTR;
  smech.ulParameterLen = 0;
  
  if((rv=pfl->C_SignInit(sh,&smech,hPriv)) != CKR_OK) {
    logger_error("pkcs11: C_SignInit: %s",pkcs11_ret_str(rv));
    return -1;
  }
  slen2 = *slen;
  if((rv=pfl->C_Sign(sh,(CK_BYTE_PTR)data,(CK_ULONG)datalen,(CK_BYTE_PTR)sout,(CK_ULONG *)&slen2)) != CKR_OK) {
    *slen = slen2;
    logger_error("pkcs11: C_Sign: %s",pkcs11_ret_str(rv));
    return -1;
  }
  *slen = slen2;
  return 0;
}

/*! Return the CKM_RSA_PKCS signed the contents of "bp" with the 
    private key "dc->hkp" as a new mbuf.  OR NULL is error.

   Notes:
    For smartcards "label" should be null as the pkcs11 library may not
    match them properly.

   \param bp pointer to mbuf with contents to sign
   \param vdc void casted pointer to pkcs11 key struct of key to sign with
   \return NULL if error; new mbuf with signed result otherwise
 */
mbuf *pkcs11_pkcssign(mbuf *bp,void *vdc)
{
  int i;
  int rv;
  CK_SESSION_HANDLE      sh;
  CK_FUNCTION_LIST_PTR pfl;
  pkkeycb *dc;
  pkcs11cb *pk;
  CK_OBJECT_HANDLE hk;
  CK_ULONG slen;
  mbuf *bpo;
  CK_MECHANISM smech;

  if(bp == NULL || vdc == NULL) {
    logger_error("pkcs11: NULL argument to %s",__func__);
    return NULL;
  }
  dc = (pkkeycb *)vdc;
  pk = (pkcs11cb *)dc->pk;
  if(pk == NULL) {
    logger_error("pkcs11: PKCS11 library not initialized");
    return NULL;
  }
  checkandsetenv(pk);
  if(pkcs11_login(pk)) return NULL;
  sh = pk->sh;
  pfl = pk->pfl;
  hk = (CK_OBJECT_HANDLE)dc->hkp;

  i = (int)(bp->pc - bp->p0); /* incomming bp is flat */
  slen = max(2*i,512);
  bpo = alloc_mbuf(slen);
  smech.mechanism = CKM_RSA_PKCS;
  smech.pParameter = NULL_PTR;
  smech.ulParameterLen = 0;
  if((rv=pfl->C_SignInit(sh,&smech,hk)) != CKR_OK) {
    logger_error("pkcs11: C_SignInit: %s",pkcs11_ret_str(rv));
    free(bpo);
    return NULL;
  }
  if((rv=pfl->C_Sign(sh,(CK_BYTE_PTR)bp->p0,(CK_ULONG)i,(CK_BYTE_PTR)bpo->p0,&slen)) != CKR_OK) {
    logger_error("pkcs11: C_Sign: %s",pkcs11_ret_str(rv));
    free(bpo);
    return NULL;
  }
  bpo->pc = bpo->p0 + slen;
  return bpo;
}

/*! Return a fresh mbuf filled with the DER encoded certificate matching the
    non-NULL label and id fields in "dc".

    \param vdc void casted pkcs11 key struct with HSM slot and CKA_LABEL
           and/or CKA_ID data to search the HSM for a matching certificate
    \return NULL if error; a new mbuf with DER encoded certificate otherwise
 */
mbuf *pkcs11_getcert(void *vdc)
{
  CK_RV rv;
  CK_SESSION_HANDLE      sh;
  pkkeycb *dc;
  pkcs11cb *pk;
  CK_FUNCTION_LIST_PTR pfl;
  CK_OBJECT_CLASS  certClass = CKO_CERTIFICATE;
  CK_ATTRIBUTE     template[5];
  CK_OBJECT_HANDLE hk,hKeys[PKCS11_MAX_KEYS_PER_SLOT];
  CK_ULONG ofound;
  int ts;
  CK_ATTRIBUTE getattributes[] = {
    {CKA_VALUE, NULL_PTR, 0},
  };
  mbuf *bpo;

  if(vdc == NULL) {
    logger_error("pkcs11: NULL argument to %s",__func__);
    return NULL;
  }
  dc = (pkkeycb *)vdc;
  pk = (pkcs11cb *)dc->pk;
  if(pk == NULL) {
    logger_error("pkcs11: PKCS11 library not initialized");
    return NULL;
  }
  checkandsetenv(pk);
  if(pkcs11_login(pk)) return NULL;
  sh = pk->sh;
  pfl = pk->pfl;

  ts = 0;
  template[ts].type = CKA_CLASS;
  template[ts].pValue = &certClass;
  template[ts].ulValueLen = sizeof(certClass);
  ts++;
  if(dc->label) {
    template[ts].type = CKA_LABEL;
    template[ts].pValue = dc->label->p0;
    template[ts].ulValueLen = strlen((char *)dc->label->p0);
    ts++;
  }
  if(dc->id) {
    template[ts].type = CKA_ID;
    template[ts].pValue = dc->id->p0;
    template[ts].ulValueLen = (int)(dc->id->pc - dc->id->p0);
    ts++;
  }
  if((rv=pfl->C_FindObjectsInit(sh,template,ts)) != CKR_OK) {
    logger_error("pkcs11: %s",__func__,pkcs11_ret_str(rv));
    return NULL;
  }

  ofound = 0;
  if((rv=pfl->C_FindObjects(sh,hKeys,PKCS11_MAX_KEYS_PER_SLOT,(CK_RV *)&ofound)) != CKR_OK) return NULL;
  if((rv=pfl->C_FindObjectsFinal(sh)) != CKR_OK) return NULL;
  if(ofound <= 0) {
    logger_error("pkcs11: No certs labeled %s found",dc->label->p0);
    return NULL;
  }
  /*printf("pkcs11: Found %d cert(s)\n",ofound);*/
  if(ofound > 1) {
    logger_error("pkcs11: Found %d duplicate certs labeled %s",ofound,dc->label->p0);
    return NULL;
  }
  hk = hKeys[0];
  if((rv=pfl->C_GetAttributeValue(sh,hk,getattributes,1)) != CKR_OK) {
    logger_error("pkcs11: C_GetAttributeValue: %s",pkcs11_ret_str(rv));
    return NULL;
  }
  bpo = alloc_mbuf(getattributes[0].ulValueLen + 4);
  getattributes[0].pValue = bpo->p0;
  if((rv=pfl->C_GetAttributeValue(sh,hk,getattributes,1)) != CKR_OK) {
    logger_error("pkcs11: C_GetAttributeValue: %s",pkcs11_ret_str(rv));
    free(bpo);
    return NULL;
  }
  bpo->pc = bpo->p0 + getattributes[0].ulValueLen;
  return bpo;
}

/*! returns base32 of time()

    Note: this routine does block (sleep) between calls to ensure a
    unique monotonically increasing base32 strings result.

    \return ASCII version of base32 repeesentation of seconds (i.e.,time())
 */
static char *get_monotonic_str()
{
  char *out;
  size_t outsize = 10;
  time_t t;
  static time_t t1=0;

  if(t1) { /* since we are dropping the last base32 char, wait to gurantee uniqueness */
    int i;

    i = 4 - (time(NULL) - t1); /* need at least 4 sec for the second digit to change */
    if(i > 0) sleep(i);
  }
  if((out=(char *)pkcs11_malloc(outsize+1)) == NULL) return NULL;
  t1 = time(NULL);
  t = htonl(t1);
  base32_encode(out, &outsize, (void *) &t, sizeof(time_t));
  out[6] = '\0';
  return out;
}

/*! Generates a "bits" bit RSA key with label based on "flags"
    in the first HSM pkcs11_init() found.

    The CKA_LABEL is based on a time based sting for uniquness.
    However duplicates are checked for in this routine nonetheless.
    Returns NULL on fail otherwise returns filled in struct.
    A later call to fillinkinfo() will populate DNSSEC key info.
    Note: label/id limited to 7 bytes due to AEP HSM display.

   \param bits number of bits for RSA key pair to generate
   \param flags Sets prefix for key label in HSM. 256=Z 257=K 0=C or U by default
   \return NULL if error or void casted pointer to new pkcs11 key struct
 */
void *pkcs11_genrsakey(int bits,int flags)
{
  CK_RV rv;
  CK_SESSION_HANDLE      sh;
  pkcs11cb *pk;
  CK_FUNCTION_LIST_PTR pfl;
  CK_OBJECT_HANDLE hPub,hPriv;
  CK_OBJECT_CLASS  class_public_key = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS  class_private_key = CKO_PRIVATE_KEY;
  CK_UTF8CHAR      Plabel8[8];
  CK_UTF8CHAR      Slabel8[8];
  CK_UTF8CHAR      Pid8[8];
  CK_UTF8CHAR      Sid8[8];
  CK_KEY_TYPE      key_type = CKK_RSA;
  CK_BYTE          rsa_exponent[] = {0x01,0x00,0x01};
  CK_MECHANISM mechanism_gen = {CKM_RSA_PKCS_KEY_PAIR_GEN,NULL_PTR,0};
  CK_ULONG modulusBits = bits;
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_LABEL,           Plabel8,           sizeof(Plabel8)-1},
    {CKA_ID,              Pid8,              sizeof(Pid8)-1}, /* arb bytes string */
    {CKA_CLASS,           &class_public_key, sizeof(class_public_key)},
    {CKA_KEY_TYPE,        &key_type,         sizeof(key_type)},
    {CKA_TOKEN,           &ctrue,            sizeof(CK_BBOOL)}, /* bTrue if put in HSM */
    {CKA_ENCRYPT,         &ctrue,            sizeof(CK_BBOOL)},
    {CKA_VERIFY,          &ctrue,            sizeof(CK_BBOOL)},
    {CKA_EXTRACTABLE,     &ctrue,            sizeof(CK_BBOOL)},
    {CKA_WRAP,            &cfalse,           sizeof(CK_BBOOL)},
    {CKA_MODULUS_BITS,    &modulusBits,      sizeof(modulusBits)},
    {CKA_PUBLIC_EXPONENT, rsa_exponent,      sizeof(rsa_exponent)},
  };
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_LABEL,       Slabel8,            sizeof(Slabel8)-1},
    {CKA_ID,          Sid8,               sizeof(Sid8)-1}, /* arb bytes string */
    {CKA_CLASS,       &class_private_key, sizeof(class_private_key)},
    {CKA_KEY_TYPE,    &key_type,          sizeof(key_type)},
    {CKA_TOKEN,       &ctrue,             sizeof(CK_BBOOL)}, /* bTrue if put in HSM */
    {CKA_DECRYPT,     &ctrue,             sizeof(CK_BBOOL)},
    {CKA_SIGN,        &ctrue,             sizeof(CK_BBOOL)},
    {CKA_EXTRACTABLE, &ctrue,             sizeof(CK_BBOOL)}, /* if API EXPORT enabled*/
    {CKA_UNWRAP,      &cfalse,            sizeof(CK_BBOOL)},
    {CKA_DERIVE,      &cfalse,            sizeof(CK_BBOOL)}, /* was true - ensure FIPS mode */
    {CKA_SENSITIVE,   &ctrue,             sizeof(CK_BBOOL)},
    {CKA_PRIVATE,     &ctrue,             sizeof(CK_BBOOL)},
  };
  CK_ATTRIBUTE getattributes[] = {
    {CKA_MODULUS, NULL_PTR, 0},
    {CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
    {CKA_ID, NULL_PTR, 0},
    {CKA_LABEL, NULL_PTR, 0},
    {CKA_MODULUS_BITS, NULL_PTR, 0}
  };
  int tries;
  CK_ULONG ts,i;
  CK_ATTRIBUTE  template[5];
  CK_OBJECT_HANDLE hKeys[PKCS11_MAX_KEYS_PER_SLOT];
  char label[10];
  pkkeycb *dc;

  pk = &pklist[0]; /* will only use first one - valid slot is selected at pkcs11_init */
  if(pk == NULL) {
    logger_error("pkcs11: PKCS11 library not initialized");
    return NULL;
  }
  checkandsetenv(pk);
  pfl = pk->pfl;
  sh = pk->sh;
  pkcs11_login(pk);

  dc = NULL;
  tries = 0;
  ts = 0; /* to satisfy "err" jump */

 regen:

  /*
   * CKA_LABEL HACK
   * AEP Keyper can only display 7 characters and
   * cannot change the HSM internal CKA_LABEL once created.
   * So, we label them with a monotonically increasing 
   * string based on seconds since epoch.
   */
  {
    int n;
    char *out;

    if((out=get_monotonic_str()) == NULL) goto err;
    if(flags == 257) snprintf(label,sizeof(label),"K%s",out);
    else if(flags == 256) snprintf(label,sizeof(label),"Z%s",out);
    else if(flags == 0) snprintf(label,sizeof(label),"C%s",out);
    else snprintf(label,sizeof(label),"U%s",out);
    free(out);
    n = strlen(label);

    /* search */
    template[0].type = CKA_LABEL;
    template[0].pValue = label;
    template[0].ulValueLen = n;
    if((rv=pfl->C_FindObjectsInit(sh,template,1)) != CKR_OK) {
      logger_error("pkcs11: %s",__func__,pkcs11_ret_str(rv));
      goto err;
    }
    if((rv=pfl->C_FindObjects(sh,hKeys,PKCS11_MAX_KEYS_PER_SLOT,&ts)) != CKR_OK) goto err;
    if((rv=pfl->C_FindObjectsFinal(sh)) != CKR_OK) goto err;
    if(ts > 0) { /* DUPLICATE - try again */
      logger_warning("Found %u duplicate keys labeled \"%s\".  Try again...",ts,label);
      if(++tries < 10) {
        sleep(1);
        goto regen;
      }
      logger_error("Can't get a unique DNSSEC tag after %d tries.  Giving up...",tries);
      goto err;
    }

    publicKeyTemplate[0].pValue = label;
    publicKeyTemplate[0].ulValueLen = n;
    publicKeyTemplate[1].pValue = label;
    publicKeyTemplate[1].ulValueLen = n;

    privateKeyTemplate[0].pValue = label;
    privateKeyTemplate[0].ulValueLen = n;
    privateKeyTemplate[1].pValue = label;
    privateKeyTemplate[1].ulValueLen = n;
  }

  /*
   * Generate a key pair
   */
  if((rv=pfl->C_GenerateKeyPair(sh,
                      &mechanism_gen,
                      publicKeyTemplate, 
                      (sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE)),
                      privateKeyTemplate, 
                      (sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE)),
                      &hPub,&hPriv)) != CKR_OK) {
    logger_error("pkcs11: C_GenerateKeyPair returned: %s",pkcs11_ret_str(rv));
    goto err;
  }

  /*
   * get exponent and modulus
   */
  ts = (sizeof(getattributes)/sizeof(CK_ATTRIBUTE));
  if((rv=pfl->C_GetAttributeValue(sh,hPub,getattributes,ts)) != CKR_OK) {
    logger_error("pkcs11: C_GetAttributeValue returned: %s",pkcs11_ret_str(rv));
    goto err;
  }
  for(i=0;i<ts;i++) getattributes[i].pValue = pkcs11_calloc(1,getattributes[i].ulValueLen + 1); /* +1 for ASCIIZ */
  if((rv=pfl->C_GetAttributeValue(sh,hPub,getattributes,ts)) != CKR_OK) {
    logger_error("pkcs11: C_GetAttributeValue returned: %s",pkcs11_ret_str(rv));
    goto err;
  }

  {
    mbuf *bp;
    int i;

    dc = (pkkeycb *)pkcs11_calloc(1,sizeof(pkkeycb));

    bp = alloc_mbuf(getattributes[2].ulValueLen + 1); /* ASCIIZ */
    memcpy(bp->p0,getattributes[2].pValue,getattributes[2].ulValueLen);
    bp->pc = bp->p0 + getattributes[2].ulValueLen;
    dc->id = bp;

    bp = alloc_mbuf(getattributes[3].ulValueLen + 1); /* ASCIIZ */
    memcpy(bp->p0,getattributes[3].pValue,getattributes[3].ulValueLen);
    bp->pc = bp->p0 + getattributes[3].ulValueLen;
    dc->label = bp;

    bp = alloc_mbuf(getattributes[0].ulValueLen);
    memcpy(bp->p0,getattributes[0].pValue,getattributes[0].ulValueLen);
    bp->pc = bp->p0 + getattributes[0].ulValueLen;
    dc->modulus = bp;

    i = getattributes[0].ulValueLen * 8;
    if(bits != i) {
      logger_warning("Key lengths differ %d != %d",dc->bits,i);
    }
    dc->bits = i;

    bp = alloc_mbuf(getattributes[1].ulValueLen);
    memcpy(bp->p0,getattributes[1].pValue,getattributes[1].ulValueLen);
    bp->pc = bp->p0 + getattributes[1].ulValueLen;
    dc->pubexp = bp;

    /* fillinkinfo(dc); was for CKA_LABEL = DNSSEC keytag */

    dc->pk = (void *)pk;
    dc->hk = (void *)hPub;
    dc->hkp = (void *)hPriv;
  }

 err:
  get_monotonic_str(); /* just call again to ensure enough time passed */
  for(i=0;i<ts;i++) {
    if(getattributes[i].pValue) free(getattributes[i].pValue);
  }

  return (void *)dc;
}

/*! delete keys matching non-null dc->label and/or dc->id from the HSM slot
    pointed to by dc->pk

    \param vdc void casted pointer to pkcs11 key struct for key to be deleted
           from HSM
    \return -1 if error; 0 if success
 */
int pkcs11_delkey(void *vdc)
{
  CK_ULONG ts,i;
  CK_RV rv;
  CK_SESSION_HANDLE      sh;
  pkkeycb *dc;
  pkcs11cb *pk;
  CK_FUNCTION_LIST_PTR pfl;
  CK_ATTRIBUTE     template[5];
  CK_OBJECT_HANDLE hKeys[PKCS11_MAX_KEYS_PER_SLOT];


  if(vdc == NULL) {
    logger_error("pkcs11: NULL argument to %s",__func__);
    return -1;
  }
  dc = (pkkeycb *)vdc;
  pk = (pkcs11cb *)dc->pk;
  if(pk == NULL) {
    logger_error("pkcs11: PKCS11 library not initialized");
    return -1;
  }
  checkandsetenv(pk);
  if(pkcs11_login(pk)) return -1;
  sh = pk->sh;
  pfl = pk->pfl;

  ts = 0;
  if(dc->label) {
    template[ts].type = CKA_LABEL;
    template[ts].pValue = dc->label->p0;
    template[ts].ulValueLen = strlen((char *)dc->label->p0);
    ts++;
  }
  if(dc->id) {
    template[ts].type = CKA_ID;
    template[ts].pValue = dc->id->p0;
    template[ts].ulValueLen = (int)(dc->id->pc - dc->id->p0);
    ts++;
  }
  if((rv=pfl->C_FindObjectsInit(sh,template,ts)) != CKR_OK) {
    logger_error("pkcs11: %s",__func__,pkcs11_ret_str(rv));
    return -1;
  }
  ts = 0;
  if((rv=pfl->C_FindObjects(sh,hKeys,PKCS11_MAX_KEYS_PER_SLOT,&ts)) != CKR_OK) return -1;
  if((rv=pfl->C_FindObjectsFinal(sh)) != CKR_OK) return -1;
  if(ts <= 0) {
    logger_warning("pkcs11: No keys labeled %s found",dc->label->p0);
    return -1;
  }
  if((ts/2) > 1) {
    logger_warning("pkcs11: Found %d duplicate public keys labeled %s",(ts/2),dc->label->p0);
  }
  for(i=0;i<ts;i++) {
    if((rv=pfl->C_DestroyObject(sh,hKeys[i])) != CKR_OK) {
      logger_error("pkcs11: C_DestroyObject: %s",pkcs11_ret_str(rv));
    }
  }
  return 0;
}

/*! convert PKCS11 return codes to ASCIIZ string
    \param rv PKCS11 library function return code
    \return corresponding string or error string
*/ 
static char *pkcs11_ret_str(CK_RV rv)
{
  switch(rv) {
  case CKR_OK:
    return "CKR_OK";
  case CKR_CANCEL:
    return "CKR_CANCEL";
  case CKR_HOST_MEMORY:
    return "CKR_HOST_MEMORY";
  case CKR_SLOT_ID_INVALID:
    return "CKR_SLOT_ID_INVALID";
  case CKR_GENERAL_ERROR:
    return "CKR_GENERAL_ERROR";
  case CKR_FUNCTION_FAILED:
    return "CKR_FUNCTION_FAILED";
  case CKR_ARGUMENTS_BAD:
    return "CKR_ARGUMENTS_BAD";
  case CKR_NO_EVENT:
    return "CKR_NO_EVENT";
  case CKR_NEED_TO_CREATE_THREADS:
    return "CKR_NEED_TO_CREATE_THREADS";
  case CKR_CANT_LOCK:
    return "CKR_CANT_LOCK";
  case CKR_ATTRIBUTE_READ_ONLY:
    return "CKR_ATTRIBUTE_READ_ONLY";
  case CKR_ATTRIBUTE_SENSITIVE:
    return "CKR_ATTRIBUTE_SENSITIVE";
  case CKR_ATTRIBUTE_TYPE_INVALID:
    return "CKR_ATTRIBUTE_TYPE_INVALID";
  case CKR_ATTRIBUTE_VALUE_INVALID:
    return "CKR_ATTRIBUTE_VALUE_INVALID";
  case CKR_DATA_INVALID:
    return "CKR_DATA_INVALID";
  case CKR_DATA_LEN_RANGE:
    return "CKR_DATA_LEN_RANGE";
  case CKR_DEVICE_ERROR:
    return "CKR_DEVICE_ERROR";
  case CKR_DEVICE_MEMORY:
    return "CKR_DEVICE_MEMORY";
  case CKR_DEVICE_REMOVED:
    return "CKR_DEVICE_REMOVED";
  case CKR_ENCRYPTED_DATA_INVALID:
    return "CKR_ENCRYPTED_DATA_INVALID";
  case CKR_ENCRYPTED_DATA_LEN_RANGE:
    return "CKR_ENCRYPTED_DATA_LEN_RANGE";
  case CKR_FUNCTION_CANCELED:
    return "CKR_FUNCTION_CANCELED";
  case CKR_FUNCTION_NOT_PARALLEL:
    return "CKR_FUNCTION_NOT_PARALLEL";
  case CKR_FUNCTION_NOT_SUPPORTED:
    return "CKR_FUNCTION_NOT_SUPPORTED";
  case CKR_KEY_HANDLE_INVALID:
    return "CKR_KEY_HANDLE_INVALID";
  case CKR_KEY_SIZE_RANGE:
    return "CKR_KEY_SIZE_RANGE";
  case CKR_KEY_TYPE_INCONSISTENT:
    return "CKR_KEY_TYPE_INCONSISTENT";
  case CKR_KEY_NOT_NEEDED:
    return "CKR_KEY_NOT_NEEDED";
  case CKR_KEY_CHANGED:
    return "CKR_KEY_CHANGED";
  case CKR_KEY_NEEDED:
    return "CKR_KEY_NEEDED";
  case CKR_KEY_INDIGESTIBLE:
    return "CKR_KEY_INDIGESTIBLE";
  case CKR_KEY_FUNCTION_NOT_PERMITTED:
    return "CKR_KEY_FUNCTION_NOT_PERMITTED";
  case CKR_KEY_NOT_WRAPPABLE:
    return "CKR_KEY_NOT_WRAPPABLE";
  case CKR_KEY_UNEXTRACTABLE:
    return "CKR_KEY_UNEXTRACTABLE";
  case CKR_MECHANISM_INVALID:
    return "CKR_MECHANISM_INVALID";
  case CKR_MECHANISM_PARAM_INVALID:
    return "CKR_MECHANISM_PARAM_INVALID";
  case CKR_OBJECT_HANDLE_INVALID:
    return "CKR_OBJECT_HANDLE_INVALID";
  case CKR_OPERATION_ACTIVE:
    return "CKR_OPERATION_ACTIVE";
  case CKR_OPERATION_NOT_INITIALIZED:
    return "CKR_OPERATION_NOT_INITIALIZED";
  case CKR_PIN_INCORRECT:
    return "CKR_PIN_INCORRECT";
  case CKR_PIN_INVALID:
    return "CKR_PIN_INVALID";
  case CKR_PIN_LEN_RANGE:
    return "CKR_PIN_LEN_RANGE";
  case CKR_PIN_EXPIRED:
    return "CKR_PIN_EXPIRED";
  case CKR_PIN_LOCKED:
    return "CKR_PIN_LOCKED";
  case CKR_SESSION_CLOSED:
    return "CKR_SESSION_CLOSED";
  case CKR_SESSION_COUNT:
    return "CKR_SESSION_COUNT";
  case CKR_SESSION_HANDLE_INVALID:
    return "CKR_SESSION_HANDLE_INVALID";
  case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
    return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
  case CKR_SESSION_READ_ONLY:
    return "CKR_SESSION_READ_ONLY";
  case CKR_SESSION_EXISTS:
    return "CKR_SESSION_EXISTS";
  case CKR_SESSION_READ_ONLY_EXISTS:
    return "CKR_SESSION_READ_ONLY_EXISTS";
  case CKR_SESSION_READ_WRITE_SO_EXISTS:
    return "CKR_SESSION_READ_WRITE_SO_EXISTS";
  case CKR_SIGNATURE_INVALID:
    return "CKR_SIGNATURE_INVALID";
  case CKR_SIGNATURE_LEN_RANGE:
    return "CKR_SIGNATURE_LEN_RANGE";
  case CKR_TEMPLATE_INCOMPLETE:
    return "CKR_TEMPLATE_INCOMPLETE";
  case CKR_TEMPLATE_INCONSISTENT:
    return "CKR_TEMPLATE_INCONSISTENT";
  case CKR_TOKEN_NOT_PRESENT:
    return "CKR_TOKEN_NOT_PRESENT";
  case CKR_TOKEN_NOT_RECOGNIZED:
    return "CKR_TOKEN_NOT_RECOGNIZED";
  case CKR_TOKEN_WRITE_PROTECTED:
    return "CKR_TOKEN_WRITE_PROTECTED";
  case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
    return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
  case CKR_UNWRAPPING_KEY_SIZE_RANGE:
    return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
  case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
    return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
  case CKR_USER_ALREADY_LOGGED_IN:
    return "CKR_USER_ALREADY_LOGGED_IN";
  case CKR_USER_NOT_LOGGED_IN:
    return "CKR_USER_NOT_LOGGED_IN";
  case CKR_USER_PIN_NOT_INITIALIZED:
    return "CKR_USER_PIN_NOT_INITIALIZED";
  case CKR_USER_TYPE_INVALID:
    return "CKR_USER_TYPE_INVALID";
  case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
    return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
  case CKR_USER_TOO_MANY_TYPES:
    return "CKR_USER_TOO_MANY_TYPES";
  case CKR_WRAPPED_KEY_INVALID:
    return "CKR_WRAPPED_KEY_INVALID";
  case CKR_WRAPPED_KEY_LEN_RANGE:
    return "CKR_WRAPPED_KEY_LEN_RANGE";
  case CKR_WRAPPING_KEY_HANDLE_INVALID:
    return "CKR_WRAPPING_KEY_HANDLE_INVALID";
  case CKR_WRAPPING_KEY_SIZE_RANGE:
    return "CKR_WRAPPING_KEY_SIZE_RANGE";
  case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
    return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
  case CKR_RANDOM_SEED_NOT_SUPPORTED:
    return "CKR_RANDOM_SEED_NOT_SUPPORTED";
  case CKR_RANDOM_NO_RNG:
    return "CKR_RANDOM_NO_RNG";
  case CKR_DOMAIN_PARAMS_INVALID:
    return "CKR_DOMAIN_PARAMS_INVALID";
  case CKR_BUFFER_TOO_SMALL:
    return "CKR_BUFFER_TOO_SMALL";
  case CKR_SAVED_STATE_INVALID:
    return "CKR_SAVED_STATE_INVALID";
  case CKR_INFORMATION_SENSITIVE:
    return "CKR_INFORMATION_SENSITIVE";
  case CKR_STATE_UNSAVEABLE:
    return "CKR_STATE_UNSAVEABLE";
  case CKR_CRYPTOKI_NOT_INITIALIZED:
    return "CKR_CRYPTOKI_NOT_INITIALIZED";
  case CKR_CRYPTOKI_ALREADY_INITIALIZED:
    return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
  case CKR_MUTEX_BAD:
    return "CKR_MUTEX_BAD";
  case CKR_MUTEX_NOT_LOCKED:
    return "CKR_MUTEX_NOT_LOCKED";
  case CKR_FUNCTION_REJECTED:
    return "CKR_FUNCTION_REJECTED";
  case CKR_VENDOR_DEFINED:
    return "CKR_VENDOR_DEFINED";
  default:
    return "Undefined Return Code";
  }
}

/***************************************************************
 * end
 ***************************************************************/
