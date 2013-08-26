#!/bin/sh
#
# $Id: svnignore.sh 435 2010-06-10 20:46:40Z jakob $

find . -type d -name '.svn' -prune -o -type d -print |\
xargs svn propset -F `dirname $0`/svnignore.txt svn:ignore 
