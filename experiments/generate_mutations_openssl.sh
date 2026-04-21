#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VALID="$ROOT/corpus/valid/openssl"
MUT="$ROOT/corpus/mutated/openssl"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src"

if [ ! -d "$VALID" ]; then
  echo "Missing valid OpenSSL corpus. Run ./experiments/generate_corpus_openssl.sh first."
  exit 1
fi

mkdir -p "$MUT"

if [ -e "$MUT/openssl_mut_mlkem768_keyusage_digital_signature_cert.pem" ]; then
  echo "reusing frozen OpenSSL mutations at $MUT"
else
  openssl x509 -new -force_pubkey "$VALID/openssl_mlkem768_ee_pub.pem" -CA "$VALID/openssl_mldsa65_ca_cert.pem" -CAkey "$VALID/openssl_mldsa65_ca_key.pem" -out "$MUT/openssl_mut_mlkem768_keyusage_digital_signature_cert.pem" -subj /CN=pqc-assurance-mut-mlkem768-digitalSignature -days 30 -set_serial 1768 -extfile "$ROOT/experiments/openssl_exts.cnf" -extensions mlkem_bad_digital_signature

  openssl req -new -x509 -key "$VALID/openssl_mldsa65_ee_key.pem" -out "$MUT/openssl_mut_mldsa65_keyusage_key_encipherment_cert.pem" -subj /CN=pqc-assurance-mut-mldsa65-keyEncipherment -days 30 -addext keyUsage=critical,keyEncipherment -addext basicConstraints=critical,CA:false
fi

python3 -B -m pqc_x509_assurance.corpus_manifest --root "$ROOT" --out "$ROOT/corpus/manifest.jsonl"

echo "generated OpenSSL mutations in $MUT"
echo "updated $ROOT/corpus/manifest.jsonl"
