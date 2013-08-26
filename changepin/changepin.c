/*
 * $Id: changepin.c 567 2010-10-28 05:11:10Z jakob $
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <ctype.h>
#include <sys/param.h>
#include "cryptoki.h"


typedef unsigned char uint8;
#define min(x,y) ((x)<(y)?(x):(y))

#define BUFFERSIZ 8192
#define MAX_SLOTS 100
#define MAX_KEYS_PER_SLOT 64

static CK_FUNCTION_LIST_PTR  pfl;

static char *pkcs11_ret_str(CK_RV rv);
int lparse(char *line,char *argv[],int maxargs,char delc);
int str_cleanup(char *io);
char *fgetsne(char *bufin,int bufinsize,FILE *streamin);
int scanhsms(char *otherdir);
#define PKCS11_HSMCONFIGDIR "/opt/dnssec"

/*! routine to change HSM USER PIN

    \param argc number of arguments
    \param argv array of pointers to arguments
    \return -1 if error; 0 if success
 */
int main(int argc,char *argv[])
{
  CK_C_GetFunctionList   pGFL=0;
  CK_RV                  rv;
  CK_ULONG               nslots;
  CK_SLOT_ID             slots[MAX_SLOTS];
  CK_SESSION_HANDLE      sh;
  void                   *hLib;
  int                    k,initslot;
  char                   *p,lbuf[512];  
  char                   *opin,*npin;

  /*
   * The dynamic lib will also need to know where libs are so:
   *  export KEYPER_LIBRARY_PATH=$PWD
   *  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$KEYPER_LIBRARY_PATH
   *
   */
  scanhsms(PKCS11_HSMCONFIGDIR);
  if((p=getenv("PKCS11_LIBRARY_PATH")) == NULL) {
    fprintf(stderr,"You must set PKCS11_LIBRARY_PATH, e.g.,\n \"export PKCS11_LIBRARY_PATH=/home/dnssec/AEP/pkcs11.so.3.10\"\n");
    return -1;
  }
  sprintf(lbuf,"%s",p);
  hLib = dlopen(lbuf,RTLD_LAZY);
  if(!hLib) {
    fprintf(stderr,"pkcs11: error: failed to open lib %s\n",lbuf);
    return -1;
  }
  if((pGFL=(CK_C_GetFunctionList)dlsym(hLib,"C_GetFunctionList")) == NULL) {
    fprintf(stderr,"pkcs11: error: Cannot find GetFunctionList()\n");
    dlclose(hLib);
    return -1;
  }
  if((rv=pGFL(&pfl)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetFunctionList: %s\n",pkcs11_ret_str(rv));
    return -1;
  }
  if((rv=pfl->C_Initialize(NULL)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_Initialize: %s\n",pkcs11_ret_str(rv));
    return -1;
  }
  nslots = MAX_SLOTS;
  if((rv=pfl->C_GetSlotList(TRUE,slots,&nslots)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_Getslots: %s\n",pkcs11_ret_str(rv));
    return -1;
  }
  if(nslots == 0) {
    fprintf(stderr,"Could not find any valid slots using %s\n",lbuf);
    return -1;
  }
  fprintf(stderr,"Found %d Slots\n",(int)nslots);/**/
  k = 0;
  if(nslots > 1) {
    fprintf(stderr,"Found %d slots. Enter slot number to operate on (0):",(int)nslots);
    if(fgets(lbuf,sizeof(lbuf),stdin) == NULL) {
      return -1;
    }
    str_cleanup(lbuf);
    k = atoi(lbuf);
    fprintf(stderr,"%d\n",k);
  }

  if(strcmp(argv[0],"pkcs11-initslot") == 0) initslot = 1;
  else initslot = 0;

  /*
   * Initialize a HSM SLOT. CAUTION: Will delete all data and associated 
   * files for an existing HSM Slot.
   */
  if(initslot) {
    char *label;
    CK_UTF8CHAR_PTR sopin = (CK_UTF8CHAR_PTR)"11223344";
    CK_UTF8CHAR slotlabel[32];

    fprintf(stderr,"Enter New label for slot %d (< 32 chars): ",k);
    if(fgetsne(lbuf,sizeof(lbuf),stdin) == NULL) {
      goto endit;
    }
    str_cleanup(lbuf);
    lbuf[32] = '\0';
    label = strdup(lbuf);

    fprintf(stderr,"Enter New PIN for slot %d labeled \"%s\": ",k,label);
    if(fgetsne(lbuf,sizeof(lbuf),stdin) == NULL) {
      goto endit;
    }
    str_cleanup(lbuf);
    npin = strdup(lbuf);
    fprintf(stderr,"Re-enter New PIN for slot %d labeled \"%s\": ",k,label);
    if(fgetsne(lbuf,sizeof(lbuf),stdin) == NULL) {
      goto endit;
    }
    str_cleanup(lbuf);
    if(strcmp(npin,lbuf)) {
      fprintf(stderr," new PINs dont match! Try again\n");
      goto endit;
    }

    memset(slotlabel,' ',sizeof(slotlabel));
    memcpy(slotlabel,label,strlen(label));
    rv = pfl->C_InitToken(slots[k],sopin,strlen((char *)sopin),slotlabel);
    if(rv != CKR_OK) {
      fprintf(stderr,"pkcs11: error: Could not InitToken %d\n C_InitToken: %s\n",k,pkcs11_ret_str(rv));
      return -1;
    }

    rv = pfl->C_OpenSession(slots[k],CKF_RW_SESSION|CKF_SERIAL_SESSION,NULL,NULL,&sh);
    if(rv != CKR_OK) {
      fprintf(stderr,"pkcs11: error: Could not open slot %d\n C_OpenSession: %s\n",k,pkcs11_ret_str(rv));
      return -1;
    }

    {
      CK_TOKEN_INFO token_info;

      if((rv = pfl->C_GetTokenInfo(slots[k],&token_info)) == CKR_OK) {
	token_info.label[31] = '\0';
	token_info.manufacturerID[31] = '\0';
	token_info.model[15] = '\0';
	token_info.serialNumber[15] = '\0';
	fprintf(stdout,"Name:%s\n",token_info.label);
	fprintf(stdout,"Mfr:%s\n",token_info.manufacturerID);
	fprintf(stdout,"Model:%s\n",token_info.model);
	fprintf(stdout,"Serial:%s\n",token_info.serialNumber);
      }
    }

    /* login as the Security Officer */
    if((rv=pfl->C_Login(sh,CKU_SO,sopin,strlen((char *)sopin))) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: Invalid PIN\n C_Login: %s\n",pkcs11_ret_str(rv));
      goto endit;
    }

    /* set the PIN for this slot */
    if((rv=pfl->C_InitPIN(sh,(CK_UTF8CHAR_PTR)npin,strlen(npin))) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: Cannot init PIN\n C_InitPin: %s\n",pkcs11_ret_str(rv));
      goto endit;
    }
    fprintf(stderr,"PIN initialized for slot %d label \"%s\". Testing...\n",k,label);

    if((rv=pfl->C_Logout(sh)) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_Logout: %s\n",pkcs11_ret_str(rv));
    }

    /* test it by loging in as a user */
    if((rv=pfl->C_Login(sh,CKU_USER,(CK_UTF8CHAR_PTR)npin,strlen(npin))) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: Invalid PIN\n C_Login: %s\n",pkcs11_ret_str(rv));
      goto endit;
    }

    fprintf(stderr,"Ok.\n");

    goto endit;
  }

  rv = pfl->C_OpenSession(slots[k],CKF_RW_SESSION|CKF_SERIAL_SESSION,NULL,NULL,&sh);
  if(rv != CKR_OK) {
    fprintf(stderr,"pkcs11: error: Could not open slot %d\n C_OpenSession: %s\n",k,pkcs11_ret_str(rv));
    return -1;
  }

  {
    CK_TOKEN_INFO token_info;

    if((rv = pfl->C_GetTokenInfo(slots[k],&token_info)) == CKR_OK) {
      token_info.label[31] = '\0';
      token_info.manufacturerID[31] = '\0';
      token_info.model[15] = '\0';
      token_info.serialNumber[15] = '\0';
      fprintf(stdout,"Name:%s\n",token_info.label);
      fprintf(stdout,"Mfr:%s\n",token_info.manufacturerID);
      fprintf(stdout,"Model:%s\n",token_info.model);
      fprintf(stdout,"Serial:%s\n",token_info.serialNumber);
    }
  }

  fprintf(stderr,"Enter Old PIN for slot %d: ",k);
  if(fgetsne(lbuf,sizeof(lbuf),stdin) == NULL) {
    goto endit;
  }
  str_cleanup(lbuf);
  if((rv=pfl->C_Login(sh,CKU_USER,(CK_UTF8CHAR_PTR)lbuf,strlen(lbuf))) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: Invalid PIN\n C_Login: %s\n",pkcs11_ret_str(rv));
    goto endit;
  }
  opin = strdup(lbuf);

  fprintf(stderr,"Enter New PIN for slot %d: ",k);
  if(fgetsne(lbuf,sizeof(lbuf),stdin) == NULL) {
    goto endit;
  }
  str_cleanup(lbuf);
  npin = strdup(lbuf);
  fprintf(stderr,"Re-enter New PIN for slot %d: ",k);
  if(fgetsne(lbuf,sizeof(lbuf),stdin) == NULL) {
    goto endit;
  }
  str_cleanup(lbuf);
  if(strcmp(npin,lbuf)) {
    fprintf(stderr," new PINs dont match! Try again\n");
    goto endit;
  }

  if((rv=pfl->C_SetPIN(sh,(CK_UTF8CHAR_PTR)opin,strlen(opin),(CK_UTF8CHAR_PTR)lbuf,strlen(lbuf))) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: Invalid PIN\n C_SetPin: %s\n",pkcs11_ret_str(rv));
    goto endit;
  }
  fprintf(stderr,"PIN change for slot %d sucessful\n",k);

 endit:
  if((rv=pfl->C_Logout(sh)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_Logout: %s\n",pkcs11_ret_str(rv));
  }
  if((rv=pfl->C_CloseSession(sh)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_CloseSession: %s\n",pkcs11_ret_str(rv));
  }
  return 0;
}

/*! an attempt to have a local ctrl-c able noecho fgets

    \param s pointer to buffer to receive characters
    \param n size of above buffer
    \param fp file pointer to open input file

    \return pointer to the buffer filled in or NULL if no chars
*/
/*#include <curses.h>*/
char *fgetsne(char *s,int n, FILE *fp)
{
  char *p;
  /*noecho();*/
  p = fgets(s,n,fp);
  /*echo();*/
  return p;
}


#include <dirent.h>
#define LBUFLEN MAXPATHLEN
static char fname[LBUFLEN];
#define NARGS 20

/*! configure HSM environment variables

    \param otherdir If non-null then path to other directory to scan for HSM
           configuration files in addition to the current directory. config files
           in current directory take precedence.

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
    fprintf(stderr,"Cannot open %s directory\n",scandir);
    return ret;
  }

  while((dp = readdir(dirp))) {

    if(strcmp(dp->d_name,".") == 0 || strcmp(dp->d_name,"..") == 0)
      continue;

    if((p=strrchr(dp->d_name,'.')) == NULL) continue;
    if(strcmp(p,".hsmconfig")) continue;

    sprintf(fname,"%s/%s",scandir,dp->d_name);
    if((fp=fopen(fname,"r")) == NULL) {
      fprintf(stderr,"warning: Cant open %s\n",fname);
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
    if((p=getenv("PKCS11_LIBRARY_PATH")) == NULL) {
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

/*! parse line /w delc as delimiter into no more than maxargs in argv[]
    skipping whitespace (' ' and tab).  Return the number of args 

    \param line pointer to buffer to be parsed
    \param argv array of maxargs pointers to be filled in with pointers into line
    \param maxargs size of pointer array above
    \param delc delimiter character
    \return number of items parsed
*/
int lparse(char *line,char *argv[],int maxargs,char delc)
{
  char *cp;
  int argc,qflag;

  if((cp = strchr(line,'\r')) != (char *)0) *cp = '\0';
  if((cp = strchr(line,'\n')) != (char *)0) *cp = '\0';

  for(argc=0;argc<maxargs;argc++) argv[argc] = (char *)0;

  for(argc=0;argc<maxargs;) {
    qflag = 0;
    while(*line == ' ' || *line == '\t') line++; /* whitespace */
    if(*line == '\0') break; /* done */
    if(*line == '"') { line++; qflag = 1; } /* quote */
    argv[argc++] = line;
    if(qflag) {                         /* quote */
      if((line = strchr(line,'"')) == (char *)0) return -1; /*error*/
      *line++ = '\0';
    } else {
      for(cp=line;*cp;cp++) {
        if(*cp == delc) break;
      }
      if(*cp) *cp++ = '\0'; /* non-zero */
      line = cp;
    }
  }
  return argc;
}

/* remove preceeding and trailing whitespace...and trailing cr and lf 

   \param io pointer to buffer that will be modified in place
   \return -1 on error; 0 if success
*/
int str_cleanup(char *io)
{
  char *q,*p;

  if (io == NULL) return -1;

  /* rid trailing space (' ' or tab) and CF/LF */
  for(q = io + strlen(io);q-- != io && isspace(*q) ;) ;

  *(q+1) = '\0';
  
  /* rid leading space */
  for(q=io;isblank(*q);q++) ;
  for(p=io;*q;) *p++ = *q++;
  *p = '\0';

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
