#!/bin/env bash
set -eu

out_certs_dir=./test/.tmp/testcerts
signing_rsa_bits=2048
signing_exponent=65537

function gen_rsa_root_cert() {
    echo "basicConstraints=CA:TRUE" > ${out_certs_dir}/ext.cnf
    openssl req -noenc -newkey rsa:3072 -pkeyopt rsa_keygen_pubexp:65537 -keyout ${out_certs_dir}/root.key -out ${out_certs_dir}/root.csr -subj "/C=US/ST=CA/L=Santa Clara/O=Example/CN=Test for Intel SGX Attestation Report Signing CA"
    openssl x509 -req -in ${out_certs_dir}/root.csr -signkey ${out_certs_dir}/root.key -days 10000 -out ${out_certs_dir}/root.crt -extfile ${out_certs_dir}/ext.cnf

    openssl x509 -in ${out_certs_dir}/root.crt -inform PEM -out ${out_certs_dir}/root.crt.der -outform DER
    # openssl verify -CAfile ${out_certs_dir}/root.crt ${out_certs_dir}/root.crt
}

function gen_ecdsa_root_cert() {
    openssl ecparam -name prime256v1 -genkey -noout -out ${out_certs_dir}/root.key
    openssl req -noenc -new -key ${out_certs_dir}/root.key -x509 -days 10000 -out ${out_certs_dir}/root.crt -subj "/C=US/ST=CA/L=Santa Clara/O=Example/CN=Test for Intel SGX Attestation Report Signing CA"

    openssl x509 -in ${out_certs_dir}/root.crt -inform PEM -out ${out_certs_dir}/root.crt.der -outform DER
    # openssl verify -CAfile ${out_certs_dir}/root.crt ${out_certs_dir}/root.crt
}

function gen_rsa_signing_cert() {
    echo "basicConstraints=CA:FALSE" > ${out_certs_dir}/ext.cnf
    openssl req -noenc -newkey rsa:${signing_rsa_bits} -pkeyopt rsa_keygen_pubexp:${signing_exponent} -keyout ${out_certs_dir}/signing.key -out ${out_certs_dir}/signing.csr -subj "/C=US/ST=CA/L=Santa Clara/O=Example/CN=Test for Intel SGX Attestation Report Signing"
    openssl x509 -req -in ${out_certs_dir}/signing.csr -CA ${out_certs_dir}/root.crt -CAkey ${out_certs_dir}/root.key -CAcreateserial -days 10000 -out ${out_certs_dir}/signing.crt -extfile ${out_certs_dir}/ext.cnf

    openssl x509 -in ${out_certs_dir}/signing.crt -inform PEM -out ${out_certs_dir}/signing.crt.der -outform DER
    # openssl verify -CAfile ${out_certs_dir}/root.crt ${out_certs_dir}/signing.crt
}

function gen_ecdsa_signing_cert() {
    openssl ecparam -name prime256v1 -genkey -noout -out ${out_certs_dir}/signing.key
    openssl req -noenc -new -key ${out_certs_dir}/signing.key -out ${out_certs_dir}/signing.csr -subj "/C=US/ST=CA/L=Santa Clara/O=Example/CN=Test for Intel SGX Attestation Report Signing"
    openssl x509 -req -in ${out_certs_dir}/signing.csr -CA ${out_certs_dir}/root.crt -CAkey ${out_certs_dir}/root.key -CAcreateserial -days 10000 -out ${out_certs_dir}/signing.crt

    openssl x509 -in ${out_certs_dir}/signing.crt -inform PEM -out ${out_certs_dir}/signing.crt.der -outform DER
    # openssl verify -CAfile ${out_certs_dir}/root.crt ${out_certs_dir}/signing.crt
}

function usage() {
    echo "Usage: $0 {gen_rsa_root_cert|gen_rsa_signing_cert|gen_ecdsa_root_cert|gen_ecdsa_signing_cert}"
    exit 1
}

if [ $# -eq 0 ]; then
    usage
fi

mkdir -p ${out_certs_dir}

case "$1" in
    "gen_rsa_root_cert")
        gen_rsa_root_cert
        ;;
    "gen_rsa_signing_cert")
        signing_rsa_bits=$2
        signing_exponent=$3
        gen_rsa_signing_cert
        ;;
    "gen_ecdsa_root_cert")
        gen_ecdsa_root_cert
        ;;
    "gen_ecdsa_signing_cert")
        gen_ecdsa_signing_cert
        ;;
    *)
        usage
        ;;
esac
