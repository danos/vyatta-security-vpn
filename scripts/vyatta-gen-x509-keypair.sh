#!/bin/bash

# Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# Copyright (c) 2011 Vyatta, Inc.
# All rights reserved.


# SPDX-License-Identifier: GPL-2.0-only

set -e

CN=$1
KEYTYPE=$2
KEYPARAM1=$3
DIR=/config/auth

genkeypair (){
  case "$KEYTYPE" in
    rsa)
      openssl req -new -nodes -keyout /config/auth/$CN.key1 \
                  -out /config/auth/$CN.csr \
                  -config /opt/vyatta/etc/key-pair.template
      openssl rsa -in /config/auth/$CN.key1  -out /config/auth/$CN.key
      rm -f /config/auth/$CN.key1

      ;;

    ecdsa)
      openssl ecparam -genkey -name $KEYPARAM1 -out /config/auth/$CN.key \
                      -noout # don't write the EC PARAMETERS.
                             # Strongswan parses only the first PEM object.
      openssl req -new -nodes -key /config/auth/$CN.key \
                  -out /config/auth/$CN.csr \
                  -config /opt/vyatta/etc/key-pair.template
      ;;

    *)
      echo "Unknown key-type $KEYTYPE" >&2
      exit 1

  esac
}
if [ -L $DIR/$CN.csr ] || [ -L $DIR/$CN.key ]; then
  echo "Symbolic link found for key and/or csr file, remove these and try again:"
  echo " $DIR/$CN.csr"
  echo " $DIR/$CN.key"
elif [ -e $DIR/$CN.csr ] || [ -e $DIR/$CN.key ]; then
  echo "A key and/or csr file already exist, remove these and try again:"
  echo " $DIR/$CN.csr"
  echo " $DIR/$CN.key"
else 
  genkeypair
fi
