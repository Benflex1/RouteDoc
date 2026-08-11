package clientprobe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

type tlsFixture struct {
	certificate  tls.Certificate
	roots        *x509.CertPool
	serverName   string
	root         *x509.Certificate
	intermediate *x509.Certificate
	leaf         *x509.Certificate
}

func newTLSFixture(t *testing.T, serverName string, rootsIncludeRoot bool) *tlsFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	return newTLSFixtureWithValidity(t, serverName, rootsIncludeRoot, now, now.Add(-time.Hour), now.Add(24*time.Hour))
}

func newTLSFixtureWithValidity(t *testing.T, serverName string, rootsIncludeRoot bool, now, leafNotBefore, leafNotAfter time.Time) *tlsFixture {
	t.Helper()
	now = now.UTC().Truncate(time.Second)
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "RouteDoctor Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "RouteDoctor Test Intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName}, NotBefore: leafNotBefore.UTC(), NotAfter: leafNotAfter.UTC(), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{leafDER, intermediateDER}, PrivateKey: leafKey, Leaf: leafCert}
	roots := x509.NewCertPool()
	if rootsIncludeRoot {
		roots.AddCert(rootCert)
	}
	return &tlsFixture{certificate: cert, roots: roots, serverName: serverName, root: rootCert, intermediate: intermediateCert, leaf: leafCert}
}

func (f *tlsFixture) serve(conn net.Conn) {
	server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.certificate}, NextProtos: []string{"http/1.1"}})
	_ = server.Handshake()
	_ = server.Close()
}
