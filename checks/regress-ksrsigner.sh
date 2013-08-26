#!/bin/sh
#
# $Id: regress-ksrsigner.sh 389 2010-06-01 16:46:52Z jakob $

SRCDIR=${1:-`pwd`}

KSRSIGNER=../ksrsigner/ksrsigner
BASELINE=$SRCDIR/baseline

setup_environment()
{
	# clean up before testing
	rm -f ksrsigner-*.log
	rm -f *.xml*
	install -m 444 $BASELINE/ksr-*.xml .
}

check_skr()
{
	if [ ! -f $1 ]; then
		echo ""
		echo ">>>> FAILED checking SKR $1"
		echo ""
		return
	fi
	
	if diff -u $BASELINE/$1 $1; then
		echo ""
		echo ">>>> SUCCESS checking SKR $1"
		echo ""
	else
		echo ""
		echo ">>>> FAILED checking SKR $1"
		echo ""
	fi
}

setup_environment

KSR="ksr-root-2009-q4-2.xml"
SKR="skr-root-2009-q4-2.xml"
LAST_SKR=""
TYPE="partial"
KSK="KSK1"
echo ""
echo ">>>> Processing $KSR ($TYPE)"
echo ""
[ -f "$LAST_SKR" ] && cp $LAST_SKR skr.xml
$KSRSIGNER -O $KSK $KSR
check_skr $SKR

KSR="ksr-root-2010-q1-0.xml"
SKR="skr-root-2010-q1-0.xml"
LAST_SKR="skr-root-2009-q4-2.xml"
TYPE="ZSK roll"
KSK="KSK1"
echo ""
echo ">>>> Processing $KSR ($TYPE)"
echo ""
[ -f "$LAST_SKR" ] && cp $LAST_SKR skr.xml
$KSRSIGNER $KSK $KSR
check_skr $SKR

KSR="ksr-root-2010-q2-0.xml"
SKR="skr-root-2010-q2-0.xml"
LAST_SKR="skr-root-2010-q1-0.xml"
TYPE="KSK/ZSK roll"
KSK="KSK1 KSK2"
echo ""
echo ">>> Processing $KSR ($TYPE)"
echo ""
[ -f "$LAST_SKR" ] && cp $LAST_SKR skr.xml
$KSRSIGNER $KSK $KSR
check_skr $SKR

KSR="ksr-root-2010-q2-0-revoke.xml"
SKR="skr-root-2010-q2-0-revoke.xml"
LAST_SKR="skr-root-2010-q1-0.xml"
TYPE="KSK revoke"
KSK="KSK1"
echo ""
echo ">>> Processing $KSR ($TYPE)"
echo ""
[ -f "$LAST_SKR" ] && cp $LAST_SKR skr.xml
$KSRSIGNER -R $KSK $KSR
check_skr $SKR

