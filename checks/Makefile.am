# $Id: Makefile.am 436 2010-06-10 20:49:43Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.db *.p8 *.log *.status *.xml *.csr *.xml.*
SUFFIXES = .p8 .key

EXTRA_DIST = \
	$(srcdir)/*.hsmconfig.in \
	$(srcdir)/*.conf \
	$(srcdir)/*.key \
	$(srcdir)/baseline/*.csr \
	$(srcdir)/baseline/*.xml

# softHSM parameters
SOFTHSM_SO_PIN =	1234567890
SOFTHSM_PIN =		123456
SOFTHSM_ENV_SINGLE =	SOFTHSM_CONF=$(srcdir)/softhsm-single.conf
SOFTHSM_ENV_DUAL =	SOFTHSM_CONF=$(srcdir)/softhsm-dual.conf
SOFTHSM_INIT =		--init-token \
			--label softHSM \
			--so-pin $(SOFTHSM_SO_PIN) \
			--pin $(SOFTHSM_PIN)
#
SOFTHSM_HSMCONFIG = 	softhsm.hsmconfig
PKCS11SPY_HSMCONFIG = 	pkcs11spy.hsmconfig


softhsm: softhsm.status

# fill slot 0 with both rsa2048-1.key & rsa2048-2.key
# fill slot 1 with rsa2048-1.key only
# fill slot 2 with rsa2048-2.key only
softhsm.status: rsa2048-1.p8 rsa2048-2.p8
	test -x @SOFTHSM@ || echo "SoftHSM not configured"
	test -x @SOFTHSM_HSMCONFIG@ || echo "SoftHSM not configured"
	env $(SOFTHSM_ENV_SINGLE) @SOFTHSM@ $(SOFTHSM_INIT) \
		--slot 0 --label "SoftHSM (slot 0)"
	env $(SOFTHSM_ENV_DUAL) @SOFTHSM@ $(SOFTHSM_INIT) \
		--slot 1 --label "SoftHSM (slot 1)"
	env $(SOFTHSM_ENV_DUAL) @SOFTHSM@ $(SOFTHSM_INIT) \
		--slot 2 --label "SoftHSM (slot 2)"
	env $(SOFTHSM_ENV_SINGLE) @SOFTHSM@ \
		--import rsa2048-1.p8 --slot 0 \
		--id 01 --label KSK1 \
		--pin $(SOFTHSM_PIN)
	env $(SOFTHSM_ENV_SINGLE) @SOFTHSM@ \
		--import rsa2048-2.p8 --slot 0 \
		--id 02 --label KSK2 \
		--pin $(SOFTHSM_PIN)
	env $(SOFTHSM_ENV_DUAL) @SOFTHSM@ \
		--import rsa2048-1.p8 --slot 1 \
		--id 01 --label KSK1 \
		--pin $(SOFTHSM_PIN)
	env $(SOFTHSM_ENV_DUAL) @SOFTHSM@ \
		--import rsa2048-2.p8 --slot 2 \
		--id 02 --label KSK2 \
		--pin $(SOFTHSM_PIN)
	touch softhsm.status

rsa2048-1.p8: $(srcdir)/rsa2048-1.key
rsa2048-2.p8: $(srcdir)/rsa2048-2.key

.key.p8:
	@OPENSSL@ pkcs8 \
		-in $< -inform pem -nocrypt \
		-out $@ -topk8

regress: regress-kskgen regress-ksrsigner-1

regress-kskgen: softhsm
	env $(SOFTHSM_ENV_SINGLE) sh regress-kskgen.sh $(srcdir)

regress-ksrsigner-1: softhsm
	env $(SOFTHSM_ENV_SINGLE) sh regress-ksrsigner.sh $(srcdir)

regress-ksrsigner-2: softhsm
	env $(SOFTHSM_ENV_DUAL) sh regress-ksrsigner.sh $(srcdir)
