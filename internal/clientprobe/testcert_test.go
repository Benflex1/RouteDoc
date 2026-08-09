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
	certificate tls.Certificate
	roots       *x509.CertPool
	serverName  string
}

func newTLSFixture(t *testing.T, serverName string, rootsIncludeLeaf bool) *tlsFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RouteDoctor Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey, Leaf: leafCert}
	roots := x509.NewCertPool()
	if rootsIncludeLeaf {
		roots.AddCert(caCert)
	}
	return &tlsFixture{certificate: cert, roots: roots, serverName: serverName}
}

func (f *tlsFixture) serve(conn net.Conn) {
	server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.certificate}, NextProtos: []string{"http/1.1"}})
	_ = server.Handshake()
	_ = server.Close()
}
