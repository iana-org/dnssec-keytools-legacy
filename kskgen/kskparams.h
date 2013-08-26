/*
 * $Id: kskparams.h 218 2010-05-12 21:14:24Z jakob $
 *
 * This file contains static KSK generation parameters
 */

#ifndef _KSKPARAMS_H_
#define _KSKPARAMS_H_

#include "dnssec.h"

/*
 * DNSKEY Parameters
 */
#define DNSSEC_ROOT_DN "."
#define DNSSEC_KSK_FLAGS 257
#define DNSSEC_PROTO 3
#define DNSSEC_ALG RRSIG_RSASHA256
#define DNSSEC_KSK_RSA_BITS 2048

/*
 * Certificate Request Subject
 */
#define DN_O "ICANN"
#define DN_OU "IANA"
#define DN_EMAIL "dnssec@iana.org"
#define OID_DNS "1.3.6.1.4.1.1000.53"

#endif /* _KSKPARAMS_H_ */
