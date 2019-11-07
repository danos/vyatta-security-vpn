# Internal x509 test cert generator

Generates ECDSA and RSA certificates:

    $ cd docs/x509/
    $ make CN=hostA
    $ make CN=hostB

This generates:

 - one CA with RSA key
 - one CA with ECDSA key

 - creates host cert for CN=hostA with RSA key signed by RSA_CA
   * certificate as PEM
   * certificate as DER
 - creates host cert for CN=hostA with ECDSA key signed by ECDSA_CA
   * certificate as PEM
   * certificate as DER

 - creates host cert for CN=hostB with RSA key signed by RSA_CA
   * certificate as PEM
   * certificate as DER
 - creates host cert for CN=hostB with ECSDA key signed by ECDSA_CA
   * certificate as PEM
   * certificate as DER
