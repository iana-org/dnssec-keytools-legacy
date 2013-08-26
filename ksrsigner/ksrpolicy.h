/*
 * $Id: ksrpolicy.h 343 2010-05-28 07:59:27Z jakob $
 *
 * Copyright (C) 2010 Internet Corporation for Assigned Names
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ICANN+RHL DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ICANN+RHL BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _KSRPOLICY_H_
#define _KSRPOLICY_H_

#include "dnssec.h"

/*
 * This file contains all policy parameters for the KSR signer
 */


/* Length of day (in seconds) */
#define T_ONEDAY               86400

/* Number of days per slot (in days) */
#define T_STEP                 10

/* Signature validity period (in days) */
#define T_VALIDITY             15

/* ZSK Rollover Interval (in days) */
#define T_ZSKROLL              90

/* Signature validity limit (in days) */
#define T_VLIMIT               ((2*T_ZSKROLL) - 1)

/* KSK Publish Safety (in days) */
#define T_PUBLISH_SAFETY       0

 /* KSK Retire Safety (in days) */
#define T_RETIRE_SAFETY        28

/* Maximum/Minimum signature validity (in days) */
#define T_MAX_SIG_VAL          20  
#define T_MIN_SIG_VAL          15

/* Maximum/minimum signature validity overlap (in days) */
#define T_MAX_VALIDITY_OVERLAP 10
#define T_MIN_VALIDITY_OVERLAP 5

/* Default TTL (in seconds) */
#define T_DEFAULT_TTL          86400


/* KSK Signature algorithm, size and exponent */
#define KSK_RRSIG_ALG             RRSIG_RSASHA256
#define KSK_RRSIG_RSA_KEYSIZE     2048
#define KSK_RRSIG_RSA_EXPONENT    3

#define MIN_SLOTS_FOR_KSK_ROLL    9

/* Webservice settings */
#define WKSR_MAILX        "/bin/mailx"
#define WKSR_XMLLINT      "/usr/bin/xmllint"
#define WKSR_MAILADDRESS  "dnssec@iana.org"
#define WKSR_MAILSUBJECT  "New KSR received"


/* Default filenames */
#define DEFAULT_KSR_FILENAME "ksr.xml"
#define DEFAULT_SKR_FILENAME "skr.xml"


#endif /* _KSRPOLICY_H_ */
