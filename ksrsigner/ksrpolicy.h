/*
 * $Id: ksrpolicy.h 578 2011-09-13 23:24:41Z lamb $
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

#ifndef _KSRPOLICY_H_
#define _KSRPOLICY_H_

#include "dnssec.h"

/*
 * This file contains all policy parameters for the KSR signer
 */


/*! Length of day (in seconds) */
#define T_ONEDAY               86400

/*! Number of days per slot (in days) */
#define T_STEP                 10

/*! Signature validity period (in days) */
#define T_VALIDITY             15

/*! ZSK Rollover Interval (in days) */
#define T_ZSKROLL              90

/*! Signature validity limit (in days) */
#define T_VLIMIT               ((2*T_ZSKROLL) - 1)

#define T_PUBLISH_SAFETY       0   /*!< KSK Publish Safety (in days) */
#define T_RETIRE_SAFETY        28  /*!< KSK Retire Safety (in days) */
#define T_MAX_SIG_VAL          20  /*!< Max sig validity (in days) */
#define T_MIN_SIG_VAL          15  /*!< Min sig validity (in days) */
#define T_MAX_VALIDITY_OVERLAP 10  /*!< Max sig validity overlap (in days) */
#define T_MIN_VALIDITY_OVERLAP 5   /*!< Min sig validity overlap (in days) */

#define T_DEFAULT_TTL          172800  /*!< Default TTL (in seconds) */

#define KSK_RRSIG_ALG             RRSIG_RSASHA256  /*!< KSK sig algorithm */
#define KSK_RRSIG_RSA_KEYSIZE     2048             /*!< KSK sig keysize */
#define KSK_RRSIG_RSA_EXPONENT    3                /*!< KSK sig exponent */

/*! Minimum number of empty slots required for KSK roll */
#define MIN_SLOTS_FOR_KSK_ROLL    9

/* Webservice settings */
#define WKSR_MAILX        "/bin/mailx"        /*!< Path to mailx binary */
#define WKSR_XMLLINT      "/usr/bin/xmllint"  /*!< Path to xmllint binary */
#define WKSR_MAILADDRESS  "ksr-notify@icann.org"   /*!< Report email address */
#define WKSR_MAILSUBJECT  "New KSR received"  /*!< Report email subject */

#define DEFAULT_KSR_FILENAME "ksr.xml"  /*!< Default KSR filename */
#define DEFAULT_SKR_FILENAME "skr.xml"  /*!< Default SKR filename */


#endif /* _KSRPOLICY_H_ */
