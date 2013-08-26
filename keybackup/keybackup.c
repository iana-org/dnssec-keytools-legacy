/*
 * $Id: keybackup.c 567 2010-10-28 05:11:10Z jakob $
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <dlfcn.h>
#include <syslog.h>

#include "cryptoki.h"
#include "util.h"
#include "logger.h"
#include "compat.h"

#define NARGS 50
#define BUFFERSIZ 8192
#define PKCS11_MAX_SLOTS 100
#define PKCS11_MAX_KEYS_PER_SLOT 1000

#define FREE_AND_CLEAR(x) { if(x) { free(x); x = NULL; } }
#define PEM_LINE_LENGTH 64
#define LOGDIR "."

static const char *progname = "keybackup";

static CK_FUNCTION_LIST_PTR  pfl;

static CK_BBOOL ctrue = CK_TRUE;
static CK_BBOOL cfalse = CK_FALSE;

static char fname[LBUFLEN];


int delobject(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hObj);

int read_keys_into_hsm(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hWrappingkey,FILE *fp);

int display_pubkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub,int flags);
int display_privkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,int flags);
int display_secretkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hSkey,int flags);
int print_privkeyinfo(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,int flags);

int getwrapkey(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_HANDLE *hWrappingKey);
int export_pubkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub);

int wrap_and_export_privkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,CK_OBJECT_HANDLE hWrappingKey);
int listkeys(CK_SESSION_HANDLE sh,char *label);
int deletekey(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_CLASS class);

int getkey(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_CLASS class,CK_OBJECT_HANDLE *hKey);
int getkeyarray(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_CLASS iclass,CK_OBJECT_HANDLE *hKeyA,int *ofound);
int scanhsms(char *otherdir);

static char *pkcs11_ret_str(CK_RV rv);

#define PKCS11_HSMCONFIGDIR "/opt/dnssec"

int main(int argc,char *argv[])
{
  CK_C_GetFunctionList   pGFL=0;
  CK_RV                  rv;
  CK_ULONG               nslots;
  CK_SLOT_ID             slots[PKCS11_MAX_SLOTS];
  CK_SESSION_HANDLE      sh;
  CK_OBJECT_HANDLE       hKeys[PKCS11_MAX_KEYS_PER_SLOT];
  void                   *hLib;
  int                    i,k,n;
  char                   *pkcs11path;
  char                   *wrappingkeylabel,lbuf[MAXPATHLEN];
  CK_OBJECT_HANDLE       hWrappingKey;
  int                    cmd,wslot;
  char                   *keylabel;
  char                   *userpin;
  
  int original_argc = argc;
  char **original_argv = argv;


  {
    int ch;
    extern char *optarg;
    extern int optind;
    extern int optopt;
    extern int opterr;
    
    keylabel = NULL;
    wrappingkeylabel = NULL;
    userpin = NULL;
    cmd = 0;
    wslot = -1;
    while((ch=getopt(argc,argv,"Vp::s::l::w:d:D:P:S:W::")) != -1) {
      switch(ch) {
      case 'V':
        printf("%s %s %s\n", PACKAGE_TARNAME, progname, PACKAGE_VERSION);
        exit(0);
      case 'p':
      case 's':
      case 'l':
      case 'W':
        if(cmd != 0) {
          printf("error: Can only perform one action at a time.\n");
          exit(-1);
        }
        if(optarg) keylabel = optarg;
        else keylabel = NULL;
        cmd = ch;
        break;
      case 'w':
        wrappingkeylabel = optarg;
        break;
      case 'S':
        wslot = atoi(optarg);
        break;
      case 'P':
        userpin = optarg;
        break;
      case 'd':
      case 'D':
        if(cmd != 0) {
          printf("error: Can only perform one action at a time.\n");
          exit(-1);
        }
        cmd = ch;
        keylabel = optarg;
        break;
      case '?':
      default:
        printf("Usage:%s [[-l[label]][-d label][-p[label]]][-P pin][-S slot][-w wrappingkey][ < keyfile ]\n",argv[0]);
        printf(" -l[label] : lists all keys or more info on \"label\"ed key\n");
        printf(" -d label  : deletes \"label\"ed key\n");
        printf(" -D label  : deletes \"label\"ed secret key\n");
        printf(" -p[label] : outputs wrapped base64 signing key for all or \"label\"ed key\n");
        printf(" -s[label] : outputs wrapped base64 secret key for all or \"label\"ed key\n");
        printf(" -W : Only create a wrapping key in the HSM\n");
        printf(" With no arguments, reads key info created by \"-p\" to import key(s)\n");
        printf(" A specfic (un)wrapping key can be specified using\n \"-w label\" for ""\"-p,-s, and < keyfile\" operations. If specified wrapping\n key does not exist, a new one will be created inside the HSM\n");
        printf(" -P pin    : pin code\n");
        printf(" -S slot   : HSM slot number (0-n)\n");
        exit(-1);
      }
    }
    argc -= optind;
    argv += optind;
    if(cmd == 0) cmd = 'b';
  }

  /* Init log system and say hello */
  logger_init(progname, LOGDIR, LOG_STDOUT);
  logger_hello(original_argc, original_argv);

  /*
   * The dynamic lib will also need to know where libs are so:
   *  export KEYPER_LIBRARY_PATH=$PWD
   *  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$KEYPER_LIBRARY_PATH
   *
   */
  scanhsms(PKCS11_HSMCONFIGDIR);
  pkcs11path = getenv("PKCS11_LIBRARY_PATH");
  if(pkcs11path == NULL) {
    myx_syslog(LOG_ERR,"You must set PKCS11_LIBRARY_PATH, e.g.,\n \"export PKCS11_LIBRARY_PATH=/home/dnssec/AEP/pkcs11.so.3.10\"\n");
    return -1;
  }
  hLib = dlopen(pkcs11path,RTLD_LAZY);
  if(!hLib) {
    logger_error("Failed to open lib %s\n %s",pkcs11path,dlerror());
    return -1;
  }
  if((pGFL=(CK_C_GetFunctionList)dlsym(hLib,"C_GetFunctionList")) == NULL) {
    logger_error("Cannot find GetFunctionList()");
    dlclose(hLib);
    return -1;
  }
  if((rv=pGFL(&pfl)) != CKR_OK) {
    logger_error("C_GetFunctionList: %s",pkcs11_ret_str(rv));
    return -1;
  }
  if((rv = pfl->C_Initialize(NULL)) != CKR_OK) {
    logger_error("C_Initialize: %s",pkcs11_ret_str(rv));
    return -1;
  }
  nslots = PKCS11_MAX_SLOTS;
  if((rv=pfl->C_GetSlotList(TRUE,slots,&nslots)) != CKR_OK) {
    logger_error("C_Getslots: %s",pkcs11_ret_str(rv));
    /*pfl->C_Finalize(0); */
    return -1;
  }
  /*printf("Got %d Slots\n",nslots); */
  k = 0;
  if(wslot >= 0 && (int)nslots >= (wslot+1)) {
    k = wslot;
  } else
  if(nslots > 1) {
    fprintf(stderr,"Found %d slots. Enter slot number (0-%d) to operate on (0):",(int)nslots,(int)(nslots-1));
    if(fgets(lbuf,sizeof(lbuf),stdin) == NULL) {
      return -1;
    }
    str_cleanup(lbuf);
    k = atoi(lbuf);
    myx_syslog(LOG_INFO,"%d\n",k);
  }

  rv = pfl->C_OpenSession(slots[k],CKF_RW_SESSION|CKF_SERIAL_SESSION,NULL,NULL,&sh);
  if(rv != CKR_OK) {
    logger_error("Could not open slot %d\n C_OpenSession: %s",k,pkcs11_ret_str(rv));
    return -1;
  }

  if(userpin) {
    strlcpy(lbuf,userpin,sizeof(lbuf));
  } else {
    fprintf(stderr,"Enter PIN for slot %d: ",k);
    /* replace /w fgetsne() for no echo */
    if(fgets(lbuf,sizeof(lbuf),stdin) == NULL) {
      return -1;
    }
    str_cleanup(lbuf);
  }

  if((rv=pfl->C_Login(sh,CKU_USER,(CK_BYTE *)lbuf,strlen(lbuf) )) != CKR_OK) {
    logger_error("Invalid PIN\n C_Login: %s",pkcs11_ret_str(rv));
    pfl->C_CloseSession(sh); 
    return -1;
  }

  if(wrappingkeylabel == NULL) wrappingkeylabel="dnssec backup key";

  if(cmd == 'b') {
    if(getwrapkey(sh,(CK_UTF8CHAR *)wrappingkeylabel,&hWrappingKey)) {
      goto endit;
    }
    read_keys_into_hsm(sh,hWrappingKey,stdin);
    goto endit;
  } else
  if(cmd == 'l') { /* list */
    listkeys(sh,keylabel);
    goto endit;
  } else
  if(cmd == 'd') {
    deletekey(sh,(CK_UTF8CHAR *)keylabel,CKO_PRIVATE_KEY);
    deletekey(sh,(CK_UTF8CHAR *)keylabel,CKO_PUBLIC_KEY);
    goto endit;
  } else
  if(cmd == 'D') {
    myx_syslog(LOG_INFO,"Are you sure you want to delete secret key \"%s\"? [N/y]: ",keylabel);
    if(fgets(lbuf,sizeof(lbuf),stdin) == NULL) {
      return -1;
    }
    str_cleanup(lbuf);
    if(lbuf[0] == 'y' || lbuf[0] == 'Y') {
      deletekey(sh,(CK_UTF8CHAR *)keylabel,CKO_SECRET_KEY);
    } else {
      myx_syslog(LOG_INFO,"Key \"%s\" not deleted\n",keylabel);
    }
    goto endit;
  } else
  if(cmd == 'p') {
    if(getwrapkey(sh,(CK_UTF8CHAR *)wrappingkeylabel,&hWrappingKey)) {
      goto endit;
    }
    if(getkeyarray(sh,(CK_UTF8CHAR *)keylabel,CKO_PRIVATE_KEY,hKeys,&n)) {
      goto endit;
    }
    for(i=0;i<n;i++) {
      wrap_and_export_privkey(sh,hKeys[i],hWrappingKey);
    }
    if(getkeyarray(sh,(CK_UTF8CHAR *)keylabel,CKO_PUBLIC_KEY,hKeys,&n)) {
      goto endit;
    }
    for(i=0;i<n;i++) {
      export_pubkey(sh,hKeys[i]);
    }
    goto endit;
  } else
  if(cmd == 's') {
    if(getwrapkey(sh,(CK_UTF8CHAR *)wrappingkeylabel,&hWrappingKey)) {
      goto endit;
    }
    if(getkeyarray(sh,(CK_UTF8CHAR *)keylabel,CKO_SECRET_KEY,hKeys,&n)) {
      goto endit;
    }
    for(i=0;i<n;i++) {
      wrap_and_export_privkey(sh,hKeys[i],hWrappingKey);
    }
    goto endit;

  } else
  if(cmd == 'W') {
    if(getwrapkey(sh,(CK_UTF8CHAR *)wrappingkeylabel,&hWrappingKey)) {
      goto endit;
    }
    goto endit;
  } else {
    logger_error("Unknown command \"%s\"",argv[1]);
  }

 endit:

  if((rv=pfl->C_Logout(sh)) != CKR_OK) {
    logger_error("C_Logout: %s",pkcs11_ret_str(rv));
  }

  if((rv=pfl->C_CloseSession(sh)) != CKR_OK) {
    logger_error("C_CloseSession: %s",pkcs11_ret_str(rv));
  }
  /*pfl->C_Finalize(0);  never */
  return 0;
}

/*! get array of key handles matching CKA_LABEL label and type iclass from slot sh

    \param sh handle referrencing open HSM slot to search
    \param label pointer to ASCIIZ CKA_LABEL
    \param iclass CKO_[PUBLIC|PRIVATE|SECRET]_KEY
    \param hKeyA pointer to array of key handle buffers
    \param ofound pointer to int buffer to fill in with number of key handles
           found
    \return -1 if error; 0 if success
*/
int getkeyarray(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_CLASS iclass,CK_OBJECT_HANDLE *hKeyA,int *ofound)
{
  int j;
  CK_ULONG n;
  CK_RV rv;
  CK_OBJECT_CLASS class;
  CK_ATTRIBUTE template[2];

  class = iclass;
  j = 0;
  template[j].type = CKA_CLASS;
  template[j].pValue = &class;
  template[j].ulValueLen = sizeof(class);
  j++;
  if(label) {
    template[j].type = CKA_LABEL;
    template[j].pValue = label;
    template[j].ulValueLen = strlen((char *)label);
    j++;
  }
  rv = pfl->C_FindObjectsInit(sh,template,j);
  if(rv != CKR_OK) return -1;
  rv = pfl->C_FindObjects(sh,hKeyA,PKCS11_MAX_KEYS_PER_SLOT,(CK_RV *)&n);
  if(rv != CKR_OK) return -1;
  rv = pfl->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) return -1;
  if(n > 0) {
    if(label && n > 1) {
      logger_error("Found more than one key matching label:\"%s\"",label);
      return -1;
    }
  } else {
    logger_error("Found no private keys labeled:\"%s\"",label);
    return -1;
  }
  *ofound = n;
  return 0;
}

/*! get key handle for wrapping key corresponding to CKA_LABEL label from slot sh

    \param sh handle refferencing open HSM slot to search
    \param label pointer to ASCIIZ CKA_LABEL
    \param hWrappingKey pointer to key handle buffer to fill in on return
    \return -1 if error; 0 if success
 */
int getwrapkey(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_HANDLE *hWrappingKey)
{
  int i;
  CK_RV rv;
  CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
  CK_ATTRIBUTE template[2];
  CK_OBJECT_HANDLE hKeys[PKCS11_MAX_KEYS_PER_SLOT];
  CK_RV ofound;

  if(label == NULL || strlen((char *)label) == 0) {
    label = (CK_UTF8CHAR *)"dnssec backup key";
  }
  template[0].type = CKA_CLASS;
  template[0].pValue = &secretClass;
  template[0].ulValueLen = sizeof(secretClass);
  template[1].type = CKA_LABEL;
  template[1].pValue = label;
  template[1].ulValueLen = strlen((char *)label);
  if((rv=pfl->C_FindObjectsInit(sh,template,2)) != CKR_OK) { 
    logger_error("C_FindObjectsInit: %s",pkcs11_ret_str(rv)); return -1; 
  }
  if((rv=pfl->C_FindObjects(sh,hKeys,PKCS11_MAX_KEYS_PER_SLOT,&ofound)) != CKR_OK) {
    logger_error("C_FindObjects: %s",pkcs11_ret_str(rv)); return -1;
  }
  if((rv=pfl->C_FindObjectsFinal(sh)) != CKR_OK) {
    logger_error("C_FindObjectsFinal: %s",pkcs11_ret_str(rv)); return -1;
  }
  if(ofound > 0) {
    *hWrappingKey = hKeys[0];
    if(ofound > 1) {
      logger_error("Found %d (>1) wrapping keys with label:\"%s\"",ofound,label);
      for(i=0;i<(int)ofound;i++) {
        display_secretkey(sh,hKeys[i],0);
      }
      return -1;
    }
    return 0;
  } else {
    logger_warning("pkcs11: Could not find a wrapping key... Creating one labeled:\"%s\"",label);
  }

  /* gen a raw key to Wrap */
  CK_MECHANISM genmechanism = {
    CKM_DES3_KEY_GEN, NULL_PTR, 0
  };
  CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
  CK_KEY_TYPE keyType = CKK_DES3;
  /* CK_BYTE value[24]; */
  CK_ATTRIBUTE wkeytmp[] = {
    {CKA_LABEL,NULL_PTR,0},
    {CKA_CLASS,&keyClass,sizeof(keyClass)},
    {CKA_KEY_TYPE,&keyType,sizeof(keyType)},
    {CKA_TOKEN,&ctrue,sizeof(ctrue)},
    {CKA_ENCRYPT,&ctrue,sizeof(ctrue)},
    {CKA_DECRYPT,&ctrue,sizeof(ctrue)},
    {CKA_WRAP,&ctrue,sizeof(ctrue)},
    {CKA_UNWRAP,&ctrue,sizeof(ctrue)},
    {CKA_EXTRACTABLE,&ctrue,sizeof(ctrue)},
    /*{CKA_VALUE, value, sizeof(value)}, */
  };
  
  wkeytmp[0].pValue = label;
  wkeytmp[0].ulValueLen = strlen((char *)label);
  if((rv=pfl->C_GenerateKey(sh,&genmechanism,
                      wkeytmp,
                      (sizeof(wkeytmp)/sizeof(CK_ATTRIBUTE)),
                      hWrappingKey)) != CKR_OK) {
    logger_error("pkcs11: C_GenerateKey: %s",pkcs11_ret_str(rv));
    return -1;
  }

  logger_info("pkcs11: Created new wrapping key labeled:\"%s\".",label);
  logger_info(" You will need to manually export this to other HSMs you plan on");
  logger_info(" exchanging keys with using your HSM's specific backup procedures.");
  return 0;
}

/*! display keys that match CKA_LABEL label in slot referrenced by sh

    \param sh handle referrencing open HSM slot to search
    \param label pointer to ASCIIZ CKA_LABEL
    \return -1 if error; 0 if success
 */
int listkeys(CK_SESSION_HANDLE sh,char *label)
{
  CK_RV rv;
  CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
  CK_ATTRIBUTE template[2];
  CK_OBJECT_HANDLE hKeys[PKCS11_MAX_KEYS_PER_SLOT];
  CK_RV ofound;
  int i,j,flag;

  flag = 1; /* min */
  if(label) flag = 2; /* verbose */

  j = 0;
  template[j].type = CKA_CLASS;
  template[j].pValue = &pubClass;
  template[j].ulValueLen = sizeof(pubClass);
  j++;
  if(label) {
    template[j].type = CKA_LABEL;
    template[j].pValue = label;
    template[j].ulValueLen = strlen(label);
    j++;
  }    
  rv = pfl->C_FindObjectsInit(sh,template,j);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjects(sh,hKeys,PKCS11_MAX_KEYS_PER_SLOT,&ofound);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) goto endit;
  if(ofound > 0) {
    logger_info("%d public keys:",ofound);
    for(i=0;i<(int)ofound;i++) {
      display_pubkey(sh,hKeys[i],flag);
    }
  }

  j = 0;
  template[j].type = CKA_CLASS;
  template[j].pValue = &privClass;
  template[j].ulValueLen = sizeof(privClass);
  j++;
  if(label) {
    template[j].type = CKA_LABEL;
    template[j].pValue = label;
    template[j].ulValueLen = strlen(label);
    j++;
  }
  rv = pfl->C_FindObjectsInit(sh,template,j);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjects(sh,hKeys,PKCS11_MAX_KEYS_PER_SLOT,&ofound);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) goto endit;
  if(ofound > 0) {
    logger_info("%d private keys:",ofound);
    for(i=0;i<(int)ofound;i++) {
      display_privkey(sh,hKeys[i],flag);
    }
  }

  j = 0;
  template[j].type = CKA_CLASS;
  template[j].pValue = &secretClass;
  template[j].ulValueLen = sizeof(secretClass);
  j++;
  if(label) {
    template[j].type = CKA_LABEL;
    template[j].pValue = label;
    template[j].ulValueLen = strlen(label);
    j++;
  }
  rv = pfl->C_FindObjectsInit(sh,template,j);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjects(sh,hKeys,PKCS11_MAX_KEYS_PER_SLOT,&ofound);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) goto endit;
  if(ofound > 0) {
    logger_info("%d secret keys:",ofound);
    for(i=0;i<(int)ofound;i++) {
      display_secretkey(sh,hKeys[i],flag);
    }
  }
  return 0;
 endit:
  return -1;
}

/*! delete key(s) from HSM slot sh matching label and class

    \param sh handle referrencing open HSM slot to search
    \param label pointer to ASCIIZ CKA_LABEL to match
    \param class CKO_[PUBLIC|PRIVATE|SECRET]_KEY
    \return -1 if error 0 of success
 */
int deletekey(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_CLASS class)
{
  CK_RV rv;
  CK_ATTRIBUTE template[2];
  CK_OBJECT_HANDLE hKeys[PKCS11_MAX_KEYS_PER_SLOT];
  CK_OBJECT_CLASS lclass;
  CK_RV ofound;

  lclass = class;
  template[0].type = CKA_CLASS;
  template[0].pValue = &lclass;
  template[0].ulValueLen = sizeof(lclass);
  template[1].type = CKA_LABEL;
  template[1].pValue = label;
  template[1].ulValueLen = strlen((char *)label);
  rv = pfl->C_FindObjectsInit(sh,template,2);
  if(rv != CKR_OK) return -1;
  rv = pfl->C_FindObjects(sh,hKeys,PKCS11_MAX_KEYS_PER_SLOT,&ofound);
  if(rv != CKR_OK) return -1;
  rv = pfl->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) return -1;
  if(ofound > 0) {
    delobject(sh,hKeys[0]);
    if(ofound > 1) {
      logger_warning("pkcs11: Found %d(>1) keys labeled:\"%s\"",ofound,label);
    }
    return 0;
  } else {
    char *p;

    switch(lclass) {
    case CKO_PRIVATE_KEY: p = "private"; break;
    case CKO_PUBLIC_KEY: p = "public"; break;
    case CKO_SECRET_KEY: p = "secret"; break;
    default: p = "unknown"; break;
    }
    logger_error("pkcs11: No %s key labeled:\"%s\"",p,label);/**/
    return -1;
  }
}

/*! see if the HSM has a key matching label and class already in it

    \param sh handle to open HSM slot to search
    \param label pointer to ASCIIZ CKA_LABEL to match
    \param class CKO_[PUBLIC|PRIVATE|SECRET]_KEY
    \return 0 if found match; -1 otherwise
 */
int havekey(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_CLASS class)
{
  CK_RV rv;
  CK_ATTRIBUTE template[2];
  CK_OBJECT_HANDLE hKeys[PKCS11_MAX_KEYS_PER_SLOT];
  CK_OBJECT_CLASS lclass;
  CK_RV ofound;

  lclass = class;
  template[0].type = CKA_CLASS;
  template[0].pValue = &lclass;
  template[0].ulValueLen = sizeof(lclass);
  template[1].type = CKA_LABEL;
  template[1].pValue = label;
  template[1].ulValueLen = strlen((char *)label);
  rv = pfl->C_FindObjectsInit(sh,template,2);
  if(rv != CKR_OK) return -1;
  rv = pfl->C_FindObjects(sh,hKeys,PKCS11_MAX_KEYS_PER_SLOT,&ofound);
  if(rv != CKR_OK) return -1;
  rv = pfl->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) return -1;
  if(ofound > 0) {
    return 0;
  } else {
    return -1;
  }
}

/*! read keys that were encoded by this program from the fp stream unwrpping
    them with the internal HSM key referrenced by hWrappingkey (if
    appropriate) into the HSM slot referrenced by sh

    \param sh handle to open HSM slot to read keys into
    \param hWrappingkey key handle for unwrapping key
    \param fp open file pointer to read from until eof
    \return 0 if success; -1 if error
 */
int read_keys_into_hsm(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hWrappingkey,FILE *fp)
{
  char *p64,*p,lbuf[512];
  int n,j;
  char *label;
  uint8_t *id,*wrappedkey;
  int idlen = 0,moduluslen = 0,exponentlen = 0,wrappedkeylen = 0;
  CK_RV rv;
  CK_BYTE *modulus,*exponent;
  CK_OBJECT_CLASS keyclass;
  CK_KEY_TYPE keytype;
  CK_OBJECT_HANDLE htmp;

  label = NULL;
  id = NULL;
  modulus = NULL;
  exponent = NULL;
  wrappedkey = NULL;
  p64 = NULL;
  while(fgets(lbuf,sizeof(lbuf),fp)) {
    if(lbuf[0] == '#') continue;
    str_cleanup(lbuf);
    j = strlen(lbuf);
    p = strchr(lbuf,':');
    if(p64) {
      if(j > 0 && p == NULL) strcat(p64,lbuf);
      if(strchr(lbuf,'=') || j < PEM_LINE_LENGTH || p) {
        char *q,*r;
        size_t qsize;

        /*printf("%s\n",p64);*/

        if((r=strchr(p64,':')) == NULL) {
          logger_error("Malformed base64 key file format");
          goto err64;
        }
        *r++ = '\0';
        qsize = strlen(r)+4;
        if((q=(char *)malloc(qsize)) == NULL) {
          logger_error("Out of memory in %s",__func__);
          goto err64;
        }
        if((n=base64decode(r,(uint8_t *)q, qsize)) < 0) {
          logger_error("Malformed base64 encoding in key file");
          free(q);
          goto err64;
        }
        if(strcmp(p64,"modulus") == 0) {
          modulus = (CK_BYTE *)q;
          moduluslen = n;
        } else if(strcmp(p64,"exponent") == 0) {
          exponent = (CK_BYTE *)q;
          exponentlen = n;
        } else if(strcmp(p64,"wrappedkey") == 0) {
          wrappedkey = (CK_BYTE *)q;
          wrappedkeylen = n;
        } else {
          logger_warning("Unknown key record |%s|",p64);
          free(q);
        }
      err64:
        free(p64);
        p64 = NULL;
      }
    }
    if(j == 0) { /* try to import the key */
      if(label == NULL) continue; /* superfulous <LF> */
      /* check to see if key with this label is already in HSM */
      /* FIXME: keyclass is undefined here */
      if(havekey(sh,(CK_UTF8CHAR *)label,keyclass) == 0) {
        logger_error("Key labeled \"%s\" already in HSM.  Exiting...",label);
        goto endit;
      }
      logger_info("Importing %s",label);
      if(keyclass == CKO_PUBLIC_KEY) {
        CK_ATTRIBUTE template[] = {
          {CKA_CLASS,&keyclass,sizeof(keyclass)},
          {CKA_KEY_TYPE,&keytype,sizeof(keytype)},
          {CKA_TOKEN,&ctrue,sizeof(ctrue)},
          {CKA_LABEL,NULL_PTR,0},
          {CKA_ID,NULL_PTR,0},
          {CKA_WRAP,&ctrue,sizeof(ctrue)},
          {CKA_ENCRYPT,&ctrue,sizeof(ctrue)},
          {CKA_MODULUS,NULL_PTR,0},
          {CKA_PUBLIC_EXPONENT,NULL_PTR,0},
          {CKA_VERIFY,&ctrue,sizeof(ctrue)},
          {CKA_EXTRACTABLE,&ctrue,sizeof(ctrue)},
        };
        if(label == NULL || modulus == NULL || exponent == NULL) {
          logger_error("pkcs11: Incomplete info for public key");
          goto endit;
        }
        template[3].pValue = (CK_UTF8CHAR *)label;
        template[3].ulValueLen = strlen(label);
        template[4].pValue = id;
        template[4].ulValueLen = idlen;
        template[7].pValue = modulus;
        template[7].ulValueLen = moduluslen;
        template[8].pValue = exponent;
        template[8].ulValueLen = exponentlen;
        if((rv=pfl->C_CreateObject(sh,
                                   template,
                                   sizeof(template)/sizeof(CK_ATTRIBUTE),
                                   &htmp)) != CKR_OK) {
          logger_error("pkcs11: C_CreateObject: %s",pkcs11_ret_str(rv));
          goto endit;
        }
        FREE_AND_CLEAR(label);
        FREE_AND_CLEAR(id);
        FREE_AND_CLEAR(modulus);
        FREE_AND_CLEAR(exponent);
        FREE_AND_CLEAR(wrappedkey);
      } else if(keyclass == CKO_PRIVATE_KEY) {
        CK_MECHANISM uwmechanism = {
          CKM_DES3_ECB, NULL_PTR, 0
        };
        CK_ATTRIBUTE template[] = {
          {CKA_LABEL,NULL_PTR,0},
          {CKA_ID,NULL_PTR,0},
          {CKA_CLASS,&keyclass,sizeof(keyclass)},
          {CKA_KEY_TYPE,&keytype,sizeof(keytype)},
          {CKA_TOKEN,&ctrue,sizeof(ctrue)},
          {CKA_PRIVATE,&ctrue,sizeof(ctrue)},
          {CKA_SENSITIVE,&ctrue,sizeof(ctrue)},
          {CKA_EXTRACTABLE,&ctrue,sizeof(ctrue)},
          {CKA_SIGN,&ctrue,sizeof(ctrue)},
          {CKA_DECRYPT,&ctrue,sizeof(ctrue)},
        };
        if(label == NULL || wrappedkey == NULL) {
          logger_error("incomplete info for private key");
          goto endit;
        }
        template[0].pValue = (CK_UTF8CHAR *)label;
        template[0].ulValueLen = strlen(label);
        template[1].pValue = id;
        template[1].ulValueLen = idlen;
        if((rv=pfl->C_UnwrapKey(sh,&uwmechanism,
                                hWrappingkey,
                                wrappedkey,
                                wrappedkeylen,
                                template,
                                (sizeof(template)/sizeof(CK_ATTRIBUTE)),
                                &htmp)) != CKR_OK) {
          logger_error("C_UnWrapKey: %s",pkcs11_ret_str(rv));
          goto endit;
        }
        FREE_AND_CLEAR(label);
        FREE_AND_CLEAR(id);
        FREE_AND_CLEAR(modulus);
        FREE_AND_CLEAR(exponent);
        FREE_AND_CLEAR(wrappedkey);
      } else if(keyclass == CKO_SECRET_KEY) {
        CK_MECHANISM uwmechanism = {
          CKM_DES3_ECB, NULL_PTR, 0
        };
        CK_ATTRIBUTE template[] = {
          {CKA_LABEL,NULL_PTR,0},
          {CKA_ID,NULL_PTR,0},
          {CKA_CLASS,&keyclass,sizeof(keyclass)},
          {CKA_KEY_TYPE,&keytype,sizeof(keytype)},
          {CKA_TOKEN,&ctrue,sizeof(ctrue)},
          {CKA_EXTRACTABLE,&ctrue,sizeof(ctrue)},
          {CKA_ENCRYPT,&ctrue,sizeof(ctrue)},
          {CKA_DECRYPT,&ctrue,sizeof(ctrue)},
          {CKA_WRAP, &ctrue, sizeof(ctrue)},
          {CKA_UNWRAP, &ctrue, sizeof(ctrue)},
        };
        if(label == NULL || wrappedkey == NULL) {
          logger_error("incomplete info for secret key");
          goto endit;
        }
        template[0].pValue = (CK_UTF8CHAR *)label;
        template[0].ulValueLen = strlen(label);
        template[1].pValue = id;
        template[1].ulValueLen = idlen;
        if((rv=pfl->C_UnwrapKey(sh,&uwmechanism,
                                hWrappingkey,
                                wrappedkey,
                                wrappedkeylen,
                                template,
                                (sizeof(template)/sizeof(CK_ATTRIBUTE)),
                                &htmp)) != CKR_OK) {
          logger_error("C_UnWrapKey: %s",pkcs11_ret_str(rv));
          goto endit;
        }
        FREE_AND_CLEAR(label);
        FREE_AND_CLEAR(id);
        FREE_AND_CLEAR(modulus);
        FREE_AND_CLEAR(exponent);
        FREE_AND_CLEAR(wrappedkey);
      } else {
        logger_error("trying to import unknown key class");
        goto endit;
      }
      continue;
    }
    if(p64) continue;
    if(p == NULL) { /* last line of base64 encoding */
      /*fprintf(stderr,"warning: keyfile has malformed line:\n|%s|\n",lbuf);*/
      continue;
    }
    *p++ = '\0';
    if(strcmp(lbuf,"label") == 0) {
      label = strdup(p);
    } else if(strcmp(lbuf,"id") == 0) {
      char *q;
      int k;
      idlen = strlen(p)/2;
      id = (uint8_t *)malloc(idlen);
      for(q=p,k=0;k<idlen;k++,q += 2) {
        id[k] = hex2i(*q)<<4 | hex2i(*(q+1));
      }
    } else if(strcmp(lbuf,"type") == 0) {
      if(strcmp(p,"rsa") == 0) {
        keytype = CKK_RSA;
      } else if(strcmp(p,"dsa") == 0) {
        keytype = CKK_DSA;
      } else if(strcmp(p,"des3") == 0) {
        keytype = CKK_DES3;
      } else {
        keytype = 0;
        logger_error("Trying to import unknown key type |%s|",p);
      }
    } else if(strcmp(lbuf,"class") == 0) {
      if(strcmp(p,"private") == 0) {
        keyclass = CKO_PRIVATE_KEY;
      } else if(strcmp(p,"public") == 0) {
        keyclass = CKO_PUBLIC_KEY;
      } else if(strcmp(p,"secret") == 0) {
        keyclass = CKO_SECRET_KEY;
      } else {
        keytype = 0;
        logger_error("Trying to import unknown key class |%s|",p);
      }
    } else if(strcmp(lbuf,"modulus") == 0
              || strcmp(lbuf,"exponent") == 0
              || strcmp(lbuf,"wrappedkey") == 0) {
      if((p64=(char *)malloc(2048)) == NULL) {
        logger_error("Error out of memory in %s",__func__);
        continue;
      }
      sprintf(p64,"%s:",lbuf);
    } else {
      logger_warning("Unknown key record |%s|",lbuf);
    }
  }
  return 0;
 endit:
  FREE_AND_CLEAR(label);
  FREE_AND_CLEAR(id);
  FREE_AND_CLEAR(modulus);
  FREE_AND_CLEAR(exponent);
  FREE_AND_CLEAR(wrappedkey);
  return -1;
}

/*! wrap private key referrenced by hPriv with internal wrapping key
    referrenced by hWrappingKey in slot sh and print out

    \param sh handle to open HSM slot
    \param hPriv handle to private key to wrap
    \param hWrappingKey handle to wrapping key to use
    \return -1 if error; 0 if success
 */
int wrap_and_export_privkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,CK_OBJECT_HANDLE hWrappingKey)
{
  CK_RV rv;
  int ret;
  uint8_t *wrappedKeyBuf;
  CK_ULONG wkeybuflen;

  ret = -1;
  wkeybuflen = 2048; /* > ((4096bit max keylen) / (8bits/byte)) = 512 x 2 for priv exponent and other RSA key material */
  if((wrappedKeyBuf=(uint8_t *)malloc(wkeybuflen)) == NULL) goto endit;
  {
    CK_MECHANISM wmechanism = {
      CKM_DES3_ECB, NULL_PTR, 0
    };
    if((rv=pfl->C_WrapKey(sh,&wmechanism,
                          hWrappingKey,
                          hPriv,
                          wrappedKeyBuf,&wkeybuflen)) != CKR_OK) {
      logger_error("C_WrapKey: %s",pkcs11_ret_str(rv));
      goto endit;
    }
  }
  /* rdump(wrappedKeyBuf,wkeybuflen); */
  if(print_privkeyinfo(sh,hPriv,0)) goto endit;
  {
    int i,j;
    char *pl,*pl0;
    size_t psize;
    
    psize = ((4*(wkeybuflen+1))/3) + 1;
    pl = pl0 = (char *)malloc(psize);
    base64encode(pl,psize,wrappedKeyBuf,wkeybuflen);
    logger_info("Wrappedkey:");
    j = strlen(pl);
    while(j > 0) {
      for(i=0;i<min(j,PEM_LINE_LENGTH);i++) myx_syslog(LOG_INFO,"%c",*pl++);
      myx_syslog(LOG_INFO,"\n");
      j -= PEM_LINE_LENGTH;
    }
    free(pl0);
  }
  myx_syslog(LOG_INFO,"\n"); /* end of key */
  ret = 0;
 endit:
  if(wrappedKeyBuf) free(wrappedKeyBuf);
  return ret;
}
/*! print public key info for key referenced by hPub

    \param sh handle to open HSM slot
    \param hPub key handle to public key to display
    \param flags 1:CKA_LABEL only. 0,2:CKA_LABEL,class,type,modulus,exponent,bits(2)
    \return -1 if error; 0 if success
 */
int print_pubkeyinfo(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub,int flags)
{
  CK_RV rv;
  char *p;
  int i,j;
  CK_ULONG tsize;
  CK_ATTRIBUTE getattributes[] = {
    {CKA_MODULUS,NULL_PTR,0},
    {CKA_PUBLIC_EXPONENT,NULL_PTR,0},
    {CKA_ID,NULL_PTR,0},
    {CKA_LABEL,NULL_PTR,0},
    {CKA_CLASS,NULL_PTR,0},
    {CKA_KEY_TYPE,NULL_PTR,0},
    {CKA_MODULUS_BITS,NULL_PTR,0},
  };

  tsize = sizeof(getattributes)/sizeof (CK_ATTRIBUTE);
  if((rv=pfl->C_GetAttributeValue(sh,hPub,getattributes,tsize)) != CKR_OK) {
    logger_error("C_GetAttributeValue: %s",pkcs11_ret_str(rv));
    return -1;
  }
  for(i=0;i<(int)tsize;i++) {
    getattributes[i].pValue = malloc(getattributes[i].ulValueLen *sizeof(CK_VOID_PTR));
    if(getattributes[i].pValue == NULL) {
      for(j=0;j<i;j++) free(getattributes[j].pValue);
      logger_error("malloc failed in %s",__func__);
      return -1;
    }
  }
  if((rv=pfl->C_GetAttributeValue(sh,hPub,getattributes,tsize)) != CKR_OK) {
    logger_error("C_GetAttributeValue: %s",pkcs11_ret_str(rv));
    for(j=0;j<(int)tsize;j++) free(getattributes[j].pValue);
    return -1;
  }
  {
    i = getattributes[3].ulValueLen;
    p = (char *)malloc(i+1);
    memcpy(p,getattributes[3].pValue,i);
    p[i] = '\0';
    logger_info("label:%s",p);
    free(p);
  }
  if(flags == 1) goto endit;
  {
    uint8_t *pl;
    pl = (uint8_t *)getattributes[2].pValue;
    myx_syslog(LOG_INFO,"id:");
    for(i=0;i<(int)getattributes[2].ulValueLen;i++) myx_syslog(LOG_INFO,"%02x",pl[i]);
    myx_syslog(LOG_INFO,"\n");
  }
  {
    if(getattributes[4].ulValueLen < sizeof(CK_OBJECT_CLASS)) myx_syslog(LOG_INFO,"class:error\n");
    switch(*(CK_OBJECT_CLASS *)getattributes[4].pValue) {
    case CKO_PRIVATE_KEY: p = "private"; break;
    case CKO_PUBLIC_KEY: p = "public"; break;
    case CKO_SECRET_KEY: p = "secret"; break;
    default: p = "unknown"; break;
    }
    myx_syslog(LOG_INFO,"class:%s\n",p);
  }
  {
    if(getattributes[5].ulValueLen < sizeof(CK_KEY_TYPE)) myx_syslog(LOG_INFO,"type:error\n");
    switch(*(CK_KEY_TYPE *)getattributes[5].pValue) {
    case CKK_RSA: p = "rsa"; break;
    case CKK_DSA: p = "dsa"; break;
    case CKK_DES3: p = "des3"; break;
    default: p = "unknown"; break;
    }
    myx_syslog(LOG_INFO,"type:%s\n",p);
  }

  if(flags == 2) {
    uint8_t *pl;
    myx_syslog(LOG_INFO, "modulus bits: %d\n",
            *((CK_ULONG_PTR)(getattributes[6].pValue)));    
    pl = (uint8_t *)getattributes[0].pValue;
    myx_syslog(LOG_INFO,"modulus: ");
    for(i=0;i<(int)getattributes[0].ulValueLen;i++) {
      myx_syslog(LOG_INFO,"%.2x",pl[i]);
    }
    myx_syslog(LOG_INFO,"\n");
    pl = (uint8_t *)getattributes[1].pValue;
    myx_syslog(LOG_INFO,"public exponent: ");
    for(i=0;i<(int)getattributes[1].ulValueLen;i++) {
      myx_syslog(LOG_INFO,"%.2x",pl[i]);
    }
    myx_syslog(LOG_INFO,"\n");
    goto endit;
  }

  {
    char *p0;
    size_t psize;
    
    i = getattributes[0].ulValueLen;
    
    psize = ((4*(i+1))/3) + 1;
    p = p0 = (char *)malloc(psize);
    base64encode(p,psize,getattributes[0].pValue,i);
    myx_syslog(LOG_INFO,"modulus:\n");
    j = strlen(p);
    while(j > 0) {
      for(i=0;i<min(j,PEM_LINE_LENGTH);i++) myx_syslog(LOG_INFO,"%c",*p++);
      myx_syslog(LOG_INFO,"\n");
      j -= PEM_LINE_LENGTH;
    }
    free(p0);
  }
  {
    char *p0;
    size_t psize;
    
    i = getattributes[1].ulValueLen;
    psize = ((4*(i+1))/3) + 1;
    p = p0 = (char *)malloc(psize);
    base64encode(p,psize,getattributes[1].pValue,i);
    myx_syslog(LOG_INFO,"exponent:\n");
    j = strlen(p);
    while(j > 0) {
      for(i=0;i<min(j,PEM_LINE_LENGTH);i++) myx_syslog(LOG_INFO,"%c",*p++);
      myx_syslog(LOG_INFO,"\n");
      j -= PEM_LINE_LENGTH;
    }
    free(p0);
  }
 endit:
  for(j=0;j<(int)tsize;j++) free(getattributes[j].pValue);
  return 0;
}
/*! print public key

    \param sh handle to open HSM slot
    \param hPub key handle to public key
    \return -1 on error; 0 if success
 */
int export_pubkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub)
{
  if(print_pubkeyinfo(sh,hPub,0)) return -1;
  myx_syslog(LOG_INFO,"\n"); /* end of key marker */
  return 0;
}

/*! print private key info for key referenced by hPriv

    \param sh handle to open HSM slot
    \param hPriv key handle to public key to display
    \param flags 1:CKA_LABEL only. 0:CKA_LABEL,class,type
    \return -1 if error; 0 if success
 */
int print_privkeyinfo(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,int flags)
{
  CK_RV rv;
  int i,j,n;
  char *p;
  CK_ULONG tsize;
  CK_ATTRIBUTE getattributes[] = {
    {CKA_ID,NULL_PTR,0},
    {CKA_LABEL,NULL_PTR,0},
    {CKA_CLASS,NULL_PTR,0},
    {CKA_KEY_TYPE,NULL_PTR,0},
  };
  tsize = sizeof (getattributes) / sizeof (CK_ATTRIBUTE);
  if((rv=pfl->C_GetAttributeValue(sh,hPriv,getattributes,tsize)) != CKR_OK) {
    logger_error("C_GetAttributeValue: %s",pkcs11_ret_str(rv));
    goto endit;
  }
  for(i=0;i<(int)tsize;i++) {
    getattributes[i].pValue = malloc(getattributes[i].ulValueLen *sizeof(CK_VOID_PTR));
    if(getattributes[i].pValue == NULL) {
      for(j=0;j <i;j++) free(getattributes[j].pValue);
      logger_error("malloc failed in %s",__func__);
      goto endit;
    }
  }
  if((rv=pfl->C_GetAttributeValue(sh,hPriv,getattributes,tsize)) != CKR_OK) {
    logger_error("C_GetAttributeValue: %s",pkcs11_ret_str(rv));
    for(j=0;j<(int)tsize;j++) free(getattributes[j].pValue);
    goto endit;
  }
  {
    n = getattributes[1].ulValueLen;
    p = (char *)malloc(n+1);
    memcpy(p,getattributes[1].pValue,n);
    p[n] = '\0';
    logger_info("label:%s",p);
    free(p);
  }
  if(flags == 1) goto endit;
  {
    uint8_t *pu;
    pu = (uint8_t *)getattributes[0].pValue;
    myx_syslog(LOG_INFO,"id:");
    for(i=0;i<(int)getattributes[0].ulValueLen;i++) myx_syslog(LOG_INFO,"%02x",pu[i]);
    myx_syslog(LOG_INFO,"\n");
  }
  {
    if(getattributes[2].ulValueLen < sizeof(CK_OBJECT_CLASS)) myx_syslog(LOG_INFO,"class:error\n");
    switch(*(CK_OBJECT_CLASS *)getattributes[2].pValue) {
    case CKO_PRIVATE_KEY: p = "private"; break;
    case CKO_PUBLIC_KEY: p = "public"; break;
    case CKO_SECRET_KEY: p = "secret"; break;
    default: p = "unknown"; break;
    }
    myx_syslog(LOG_INFO,"class:%s\n",p);
  }
  {
    if(getattributes[3].ulValueLen < sizeof(CK_KEY_TYPE)) myx_syslog(LOG_INFO,"type:error\n");
    switch(*(CK_KEY_TYPE *)getattributes[3].pValue) {
    case CKK_RSA: p = "rsa"; break;
    case CKK_DSA: p = "dsa"; break;
    case CKK_DES3: p = "des3"; break;
    default: p = "unknown"; break;
    }
    myx_syslog(LOG_INFO,"type:%s\n",p);
  }
 endit:
  for(j=0;j<(int)tsize;j++) free(getattributes[j].pValue);
  return 0;
}

/*! wrapper for print_privkeyinfo */
int display_privkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,int flags)
{
  return print_privkeyinfo(sh,hPriv,flags);
}

/*! wrapper for print_privkeyinfo */
int display_pubkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub,int flags)
{
  return print_pubkeyinfo(sh,hPub,flags);
}

/*! wrapper for print_privkeyinfo */
int display_secretkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hSkey,int flags)
{
  return display_privkey(sh,hSkey,flags);
}

/*! destroy object hObj in slot sh

    \param sh handle to open HSM slot
    \param hObj handle to object to delete
    \return -1 if error; 0 if success
 */
int delobject(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hObj)
{
  CK_RV rv;
  if((rv=pfl->C_DestroyObject(sh,hObj)) != CKR_OK) {
    logger_error("pkcs11: C_DestroyObject: %s",pkcs11_ret_str(rv));
    return -1;
  }
  myx_syslog(LOG_INFO,"Deleted object %08x\n",hObj);
  return 0;
}
/*! set HSM environment variables using *.hsmconfig file in current directory
    and otherdir (if specified). Current directory takes precedence.

    \param otherdir if non NULL, search this directory if no suitable hsmconfig was found for current directory
    \return -1 if error; 0 if success.
 */
int scanhsms(char *otherdir)
{
  char *p,lbuf[LBUFLEN];
  DIR *dirp;
  struct dirent *dp;
  FILE *fp;
  char *scandir;
  int ret;

  scandir = ".";
  ret = -1;

 doredir:
  if((dirp = opendir(scandir)) == (DIR *)0) {
    logger_error("Cannot open %s directory",scandir);
    return ret;
  }

  while((dp = readdir(dirp))) {

    if(strcmp(dp->d_name,".") == 0 || strcmp(dp->d_name,"..") == 0)
      continue;

    if((p=strrchr(dp->d_name,'.')) == NULL) continue;
    if(strcmp(p,".hsmconfig")) continue;

    snprintf(fname,sizeof(fname),"%s/%s",scandir,dp->d_name);
    if((fp=fopen(fname,"r")) == NULL) {
      logger_warning("Can't open %s",fname);
      continue;
    }
    /*fprintf(stderr,"Using hsmconfig %s\n",fname);*/
    while(fgets(lbuf,sizeof(lbuf),fp)) {
      int n;
      char *args[NARGS];

      if(lbuf[0] == '#') continue;
      n = lparse(lbuf,args,NARGS,'=');
      if(n < 1) continue;
      if(n == 1) unsetenv(args[0]);
      else {
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
                /*fprintf(stderr,"Could not get environment variable \"%s\"\n",ev);  may be NULL */
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
        setenv(args[0],obuf,1);
      }
    }
    fclose(fp);
    if((getenv("PKCS11_LIBRARY_PATH")) == NULL) {
      /*fprintf(stderr,"You must set at least PKCS11_LIBRARY_PATH\n");*/
      continue;
    }
    /*fprintf(stderr,"PKCS11_LIBRARY_PATH=%s\n",p);*/
    ret = 0;
  }
  closedir(dirp);
  if(ret && otherdir) {
    scandir = otherdir;
    otherdir = NULL;
    goto doredir;
  }
  return ret;
}

/*! convert PKCS11 function return codes to printable strings

    \param rv PKCS11 library return code
    \return ASCIIZ string corresponding to rv code
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
