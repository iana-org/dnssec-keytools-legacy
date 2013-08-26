/*
 * $Id: dnssec.h 564 2010-10-25 06:44:08Z jakob $
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

#ifndef _DNSSEC_H_
#define _DNSSEC_H_

#include <stdint.h>
#include <unistd.h>


/* Domain Name System Security (DNSSEC) Algorithm Numbers */
#define RRSIG_DSASHA1         3
#define RRSIG_ECC             4
#define RRSIG_RSASHA1         5
#define RRSIG_DSANSEC3SHA1    6
#define RRSIG_RSANSEC3SHA1    7
#define RRSIG_RSASHA256       8
#define RRSIG_RSASHA512       10

/* Delegation Signer (DS) Resource Record (RR) Type Digest Algorithms */
#define DS_SHA1    1
#define DS_SHA256  2

/* DNSKEY Flags */
#define DNSKEY_ZONE_FLAG    0x0100
#define DNSKEY_SEP_FLAG     0x0001
#define DNSKEY_REVOKE_FLAG  0x0080

/* DNSKEY Protocol Identifiers */
#define DNSKEY_PROTOCOL_DNSSEC  3

/*! Calculate DNSSEC key tag

    \param  key  DNSKEY RDATA buffer
    \param  klen Size of buffer
    \return Key tag
*/
uint16_t dnssec_keytag(const uint8_t *key, size_t klen);

/*! Encode domain name to wire format

    \param[in]  dn   Domain Name
    \param[out] wire Buffer containing wire format encoding
    \return     Size of buffer
*/
size_t dnssec_dn2wire(const char *dn, uint8_t *wire);

#endif /* _DNSSEC_H_ */
