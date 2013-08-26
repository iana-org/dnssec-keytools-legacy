#!/bin/sh
#
# $Id: regress-kskgen.sh 284 2010-05-24 19:53:18Z jakob $

SRCDIR=${1:-`pwd`}

KSKGEN=../kskgen/kskgen
OPENSSL=openssl
BASELINE=$SRCDIR/baseline

HASH_BASELINE="DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"

get_csr_subject_pregen()
{
	SUBJECT=`$OPENSSL req -subject -noout -inform der -in $1`
		
	echo $SUBJECT | sed \
        	-e "s/....-..-..T..:..:..+..:../0000-00-00T00:00:00+00:00/"
}

get_csr_subject_random()
{
	SUBJECT=`$OPENSSL req -subject -noout -inform der -in $1`
	
	echo $SUBJECT | sed \
        	-e "s/....-..-..T..:..:..+..:../0000-00-00T00:00:00+00:00/" \
	        -e "s/IN DS [0-9]* 8 2 [0-9A-F]\{64\}/IN DS 0 8 2 ${HASH_BASELINE}/"
}

compare_csr_subject_pregen()
{
        SUBJECT_1=`get_csr_subject_pregen $1`
        SUBJECT_2=`get_csr_subject_pregen $2`

        if [ "${SUBJECT_1}" != "${SUBJECT_2}" ]; then
        	echo ""
        	echo ">>>> FAILED checking CSR subject"
        	echo ""
        else
        	echo ""
        	echo ">>>> SUCCESS checking CSR subject"
        	echo ""	
        fi
}

compare_csr_subject_random()
{
        SUBJECT_1=`get_csr_subject_random $1`
        SUBJECT_2=`get_csr_subject_random $2`

        if [ "${SUBJECT_1}" != "${SUBJECT_2}" ]; then
        	echo ""
        	echo ">>>> FAILED checking CSR subject"
        	echo ""
        else
        	echo ""
        	echo ">>>> SUCCESS checking CSR subject"
        	echo ""	
        fi
}

check_csr_syntax()
{
        if ! $OPENSSL req -verify  -noout -inform der -in $1; then
        	echo ""
        	echo ">>>> FAILED checking CSR syntax"
        	echo ""
        else
        	echo ""
        	echo ">>>> SUCCESS checking CSR syntax"
        	echo ""	
        fi
}


# test random key generation
CSR_REGRESS=random.csr
CSR_BASELINE=$BASELINE/KSK1.csr
echo ""
echo ">>>> Generating random key"
echo ""
rm -f *.csr
$KSKGEN
cp `ls -1 *.csr` $CSR_REGRESS
if [ ! -f $CSR_REGRESS ]; then
	echo ">>>> No CSR"
	exit 1
fi
check_csr_syntax $CSR_REGRESS
compare_csr_subject_random $CSR_BASELINE $CSR_REGRESS

# test pre-generated key
CSR_REGRESS=KSK1.csr
CSR_BASELINE=$BASELINE/KSK1.csr
echo ""
echo ">>>> Test pre-generated key (KSK1)"
echo ""
rm -f *.csr
$KSKGEN KSK1
if [ ! -f $CSR_REGRESS ]; then
	echo ">>>> No CSR"
	exit 1
fi
check_csr_syntax $CSR_REGRESS
compare_csr_subject_pregen $CSR_BASELINE $CSR_REGRESS
