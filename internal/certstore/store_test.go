package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidatePair(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := createCertificate(t, dir, []string{"example.com", "*.example.net"})
	info, err := ValidatePair(certFile, keyFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if info.DaysLeft < 20 {
		t.Fatalf("unexpected certificate lifetime: %+v", info)
	}
}

func createCertificate(t *testing.T, dir string, names []string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestVerifyWildcardDomain(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := createCertificate(t, dir, []string{"*.example.net"})
	data, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseLeafCertificate(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDomain(leaf, "*.example.net"); err != nil {
		t.Fatalf("wildcard should validate: %v", err)
	}
	if err := VerifyDomain(leaf, "*.other.net"); err == nil {
		t.Fatal("uncovered wildcard unexpectedly validated")
	}
	if err := os.Chmod(keyFile, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePair(certFile, keyFile, time.Now()); err != nil {
		t.Fatalf("0640 private key should be accepted: %v", err)
	}
}
