#!/bin/bash
set -e
# --- Generate CA's private key and self-signed certificate ---
openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout ca.key -out ca-cert.pem -subj "/CN=ZTA Demo Root CA"

# --- Leaf certificate, signed by a CA (*) ---
# Generate private key and certificate signing request (CSR) for subject (Admin)
openssl req -newkey rsa:2048 -nodes -keyout admin.key -out admin.csr \
  -subj "/CN=admin/OU=admin" \
  -addext "subjectAltName=URI:spiffe://zta.demo/user/admin"
# Use CA's private key to sign admin's CSR and get back the signed certificate
openssl x509 -req -in admin.csr -CA ca-cert.pem -CAkey ca.key -out admin.pem -days 365

# analogue (*) for Alice
openssl req -newkey rsa:2048 -nodes -keyout alice.key -out alice.csr \
  -subj "/CN=alice/OU=employee" \
  -addext "subjectAltName=URI:spiffe://zta.demo/user/alice"
openssl x509 -req -in alice.csr -CA ca-cert.pem -CAkey ca.key -out alice.pem -days 365 -copy_extensions copy

# --- Revoked ---
# analogue (*) for Dan, but it is compromised
openssl req -newkey rsa:2048 -nodes -keyout dan-revoked.key -out dan-revoked.csr \
  -subj "/CN=dan/OU=contractor" \
  -addext "subjectAltName=URI:spiffe://zta.demo/user/dan"
openssl x509 -req -in dan-revoked.csr -CA ca-cert.pem -CAkey ca.key -out dan-revoked.pem -days 365

# --- Expired ---
# analogue (*) for Bob, but specifying an invalid date
openssl req -newkey rsa:2048 -nodes -keyout bob-expired.key -out bob-expired.csr \
  -subj "/CN=bob/OU=employee" \
  -addext "subjectAltName=URI:spiffe://zta.demo/user/bob"
openssl x509 -req -in bob-expired.csr -CA ca-cert.pem -CAkey ca.key -out bob-expired.pem \
  -not_before 20250101000000Z \
  -not_after 20250201000000Z
openssl x509 -in bob-expired.pem -noout -enddate -text

# --- Fingerprint ---
# Generate a fingerprint from the subject's certificate using SHA256
for cert in alice admin dan-revoked bob-expired; do
    echo "--- $cert ---"
    openssl x509 -in "$cert.pem" -fingerprint -sha256 -noout
done

# --- CRL (list of revoked certificates) ---
FPR=$(openssl x509 -in dan-revoked.pem -fingerprint -sha256 -noout | cut -d= -f2)
{
    echo "# crl.txt — revoked certificates (SHA-256 fingerprint)"
    echo "$FPR"
} > crl.txt
echo "CRL written to crl.txt:"
cat crl.txt
