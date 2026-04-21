#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VALID="$ROOT/corpus/valid/openssl"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is missing; cannot generate corpus."
  exit 1
fi

mkdir -p "$VALID"

if [ -e "$VALID/openssl_mldsa65_ca_cert.pem" ]; then
  echo "reusing frozen OpenSSL corpus at $VALID"
else
  openssl genpkey -algorithm ML-DSA-65 -out "$VALID/openssl_mldsa65_ca_key.pem"
  openssl pkey -in "$VALID/openssl_mldsa65_ca_key.pem" -pubout -out "$VALID/openssl_mldsa65_ca_pub.pem"
  openssl req -new -x509 -key "$VALID/openssl_mldsa65_ca_key.pem" -out "$VALID/openssl_mldsa65_ca_cert.pem" -subj /CN=pqc-assurance-mldsa65-ca -days 30 -addext keyUsage=critical,keyCertSign,cRLSign -addext basicConstraints=critical,CA:true

  openssl genpkey -algorithm ML-DSA-44 -out "$VALID/openssl_mldsa44_ee_key.pem"
  openssl pkey -in "$VALID/openssl_mldsa44_ee_key.pem" -pubout -out "$VALID/openssl_mldsa44_ee_pub.pem"
  openssl req -new -x509 -key "$VALID/openssl_mldsa44_ee_key.pem" -out "$VALID/openssl_mldsa44_ee_cert.pem" -subj /CN=pqc-assurance-mldsa44-ee -days 30 -addext keyUsage=critical,digitalSignature -addext basicConstraints=critical,CA:false

  openssl genpkey -algorithm ML-DSA-65 -out "$VALID/openssl_mldsa65_ee_key.pem"
  openssl pkey -in "$VALID/openssl_mldsa65_ee_key.pem" -pubout -out "$VALID/openssl_mldsa65_ee_pub.pem"
  openssl req -new -x509 -key "$VALID/openssl_mldsa65_ee_key.pem" -out "$VALID/openssl_mldsa65_ee_cert.pem" -subj /CN=pqc-assurance-mldsa65-ee -days 30 -addext keyUsage=critical,digitalSignature -addext basicConstraints=critical,CA:false

  openssl genpkey -algorithm ML-DSA-87 -out "$VALID/openssl_mldsa87_ee_key.pem"
  openssl pkey -in "$VALID/openssl_mldsa87_ee_key.pem" -pubout -out "$VALID/openssl_mldsa87_ee_pub.pem"
  openssl req -new -x509 -key "$VALID/openssl_mldsa87_ee_key.pem" -out "$VALID/openssl_mldsa87_ee_cert.pem" -subj /CN=pqc-assurance-mldsa87-ee -days 30 -addext keyUsage=critical,digitalSignature -addext basicConstraints=critical,CA:false

  openssl genpkey -algorithm ML-KEM-512 -out "$VALID/openssl_mlkem512_ee_key.pem"
  openssl pkey -in "$VALID/openssl_mlkem512_ee_key.pem" -pubout -out "$VALID/openssl_mlkem512_ee_pub.pem"
  openssl x509 -new -force_pubkey "$VALID/openssl_mlkem512_ee_pub.pem" -CA "$VALID/openssl_mldsa65_ca_cert.pem" -CAkey "$VALID/openssl_mldsa65_ca_key.pem" -out "$VALID/openssl_mlkem512_ee_cert.pem" -subj /CN=pqc-assurance-mlkem512-ee -days 30 -set_serial 512 -extfile "$ROOT/experiments/openssl_exts.cnf" -extensions mlkem_ee

  openssl genpkey -algorithm ML-KEM-768 -out "$VALID/openssl_mlkem768_ee_key.pem"
  openssl pkey -in "$VALID/openssl_mlkem768_ee_key.pem" -pubout -out "$VALID/openssl_mlkem768_ee_pub.pem"
  openssl x509 -new -force_pubkey "$VALID/openssl_mlkem768_ee_pub.pem" -CA "$VALID/openssl_mldsa65_ca_cert.pem" -CAkey "$VALID/openssl_mldsa65_ca_key.pem" -out "$VALID/openssl_mlkem768_ee_cert.pem" -subj /CN=pqc-assurance-mlkem768-ee -days 30 -set_serial 768 -extfile "$ROOT/experiments/openssl_exts.cnf" -extensions mlkem_ee

  openssl genpkey -algorithm ML-KEM-1024 -out "$VALID/openssl_mlkem1024_ee_key.pem"
  openssl pkey -in "$VALID/openssl_mlkem1024_ee_key.pem" -pubout -out "$VALID/openssl_mlkem1024_ee_pub.pem"
  openssl x509 -new -force_pubkey "$VALID/openssl_mlkem1024_ee_pub.pem" -CA "$VALID/openssl_mldsa65_ca_cert.pem" -CAkey "$VALID/openssl_mldsa65_ca_key.pem" -out "$VALID/openssl_mlkem1024_ee_cert.pem" -subj /CN=pqc-assurance-mlkem1024-ee -days 30 -set_serial 1024 -extfile "$ROOT/experiments/openssl_exts.cnf" -extensions mlkem_ee
fi

python3 -B -m pqc_x509_assurance.corpus_manifest --root "$ROOT" --out "$ROOT/corpus/manifest.jsonl"

echo "generated OpenSSL corpus in $VALID"
echo "updated $ROOT/corpus/manifest.jsonl"
