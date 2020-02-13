# Copyright (c) 2018-2020 AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2016 Brocade Communications Systems, Inc.
# All rights reserved.

# SPDX-License-Identifier: GPL-2.0-only

CN   = hostA
DAYS = 365
EC   = secp384r1
DATE = $$( date +%s )
CA_SUBJECT         = "/C=US/ST=CA/L=Palo Alto/O=CompanyX/OU=Labs/CN=Vyatta R&D TEST CA $(DATE)"
HOST_SUBJECT_RSA   = "/C=US/ST=CA/L=Palo Alto/O=CompanyX/OU=Labs/CN=$(CN)"
HOST_SUBJECT_ECDSA = "/C=US/ST=CA/L=Palo Alto/O=CompanyX/OU=Labs/CN=$(CN)"
SHA_SIGNED="-SHA256"
OCSP = "http://ocsp.example.com:8888"
CRL  = "http://crl.example.com:8000/test.crl"

SAN_REQEXT=-reqexts SAN
SAN_EXT=-extensions SAN

ifneq ($(OCSP),)
OCSP_EXT=-extensions v3_OCSP
endif

all: RSA_$(CN).der RSA_$(CN).p12

sample.cnf:
	touch index.txt
	touch index.txt.attr
	echo 00 > serial
	echo 00 > crlnumber
	cp /etc/ssl/openssl.cnf sample.cnf
	sed -i 's/demoCA//g' sample.cnf
	sed -i 's/newcerts//g' sample.cnf
	echo "[SAN]" >> sample.cnf
	echo 'subjectAltName=DNS:$(CN)' >> sample.cnf
	echo '' >> sample.cnf

ifneq ($(OCSP),)
	echo "[v3_OCSP]" >> sample.cnf
	echo "basicConstraints = CA:FALSE" >> sample.cnf
	echo "keyUsage = nonRepudiation, digitalSignature, keyEncipherment" >> sample.cnf
	echo "extendedKeyUsage = OCSPSigning" >> sample.cnf
endif

	echo "[ usr_cert ]" >> sample.cnf
	echo "basicConstraints=CA:FALSE" >> sample.cnf
	echo "nsComment = \"vyatta-security-vpn doc sample\"" >> sample.cnf
	echo "subjectKeyIdentifier=hash" >> sample.cnf
	echo "authorityKeyIdentifier=keyid,issuer" >> sample.cnf
	echo "extendedKeyUsage = clientAuth, serverAuth" >> sample.cnf
ifneq ($(OCSP),)
	echo "authorityInfoAccess = OCSP;URI:$(OCSP)" >> sample.cnf
endif
ifneq ($(CRL),)
	echo "crlDistributionPoints = URI:$(CRL)" >> sample.cnf
endif


ECDSA_CA.key:
	openssl ecparam -out ECDSA_CA.key -name $(EC) -genkey

RSA_CA.key:
	openssl genrsa -out RSA_CA.key 2048 

ECDSA_CA.pem: ECDSA_CA.key
	openssl req $(SHA_SIGNED) -nodes -subj $(CA_SUBJECT) -new -key ECDSA_CA.key -x509 -days $(DAYS) -out ECDSA_CA.pem

RSA_CA.pem: RSA_CA.key
	openssl req $(SHA_SIGNED) -nodes -subj $(CA_SUBJECT) -new -key RSA_CA.key -x509 -days $(DAYS) -out RSA_CA.pem

RSA_$(CN).csr RSA_$(CN).key: sample.cnf
	# the reason for *.key1 creation is to be close to: vyatta-gen-x509-keypair.sh 
	openssl req -new -nodes -keyout RSA_$(CN).key1 -out RSA_$(CN).csr $(SAN_REQEXTS) -config sample.cnf -subj $(HOST_SUBJECT_RSA)
	openssl rsa -in RSA_$(CN).key1  -out RSA_$(CN).key
	rm -f RSA_$(CN).key1

ECDSA_$(CN).key:
	openssl ecparam -genkey -name $(EC) -out ECDSA_$(CN).key -noout

ECDSA_$(CN).csr: ECDSA_$(CN).key sample.cnf
	openssl req -new -nodes -key ECDSA_$(CN).key -out ECDSA_$(CN).csr $(SAN_REQEXTS) -config sample.cnf -subj $(HOST_SUBJECT_ECDSA)

ECDSA_$(CN).pem: ECDSA_$(CN).csr ECDSA_CA.pem sample.cnf
	openssl ca -batch -config sample.cnf -days $(DAYS) -in ECDSA_$(CN).csr -cert ECDSA_CA.pem -keyfile ECDSA_CA.key -out ECDSA_$(CN).pem -extfile sample.cnf -extensions usr_cert $(SAN_EXT) $(OCSP_EXT)

RSA_$(CN).pem: RSA_$(CN).csr RSA_CA.pem sample.cnf
	openssl ca -batch -config sample.cnf -days $(DAYS) -in RSA_$(CN).csr -cert RSA_CA.pem -keyfile RSA_CA.key -out RSA_$(CN).pem -extfile sample.cnf -extensions usr_cert $(SAN_EXT) $(OCSP_EXT)

ECDSA_$(CN).der: ECDSA_$(CN).pem
	openssl x509 -outform der -in ECDSA_$(CN).pem -out ECDSA_$(CN).der

ECDSA_$(CN).p12: ECDSA_$(CN).pem
	openssl pkcs12 -export -in ECDSA_$(CN).pem -inkey ECDSA_$(CN).key -out ECDSA_$(CN).p12 -passout "pass:vyatta"

RSA_$(CN).der:  RSA_$(CN).pem
	openssl x509 -outform der -in RSA_$(CN).pem -out RSA_$(CN).der

RSA_$(CN).p12:  RSA_$(CN).pem
	openssl pkcs12 -export -in RSA_$(CN).pem -inkey RSA_$(CN).key -out RSA_$(CN).p12 -passout "pass:vyatta"

RSA_CA.crl: RSA_CA.pem
	openssl ca -config sample.cnf -gencrl -keyfile RSA_CA.key -cert RSA_CA.pem -out RSA_CA.crl
	openssl ca -config sample.cnf -revoke RSA_$(CN).pem -keyfile RSA_CA.key -cert RSA_CA.pem
	openssl ca -config sample.cnf -gencrl -keyfile RSA_CA.key -cert RSA_CA.pem -out RSA_CA.crl

ECDSA_CA.crl: ECDSA_CA.pem
	openssl ca -config sample.cnf -gencrl -keyfile ECDSA_CA.key -cert ECDSA_CA.pem -out ECDSA_CA.crl
	openssl ca -config sample.cnf -revoke ECDSA_$(CN).pem -keyfile ECDSA_CA.key -cert ECDSA_CA.pem
	openssl ca -config sample.cnf -gencrl -keyfile ECDSA_CA.key -cert ECDSA_CA.pem -out ECDSA_CA.crl

clean:
	rm -f *.crl *.csr *.pem *.key *.srl *.der *.p12 *.key1 sample.cnf crlnumber index.txt* serial*
