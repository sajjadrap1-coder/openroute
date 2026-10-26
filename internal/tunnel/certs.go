package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const ServerName = "openroute-relay"

type PKIPaths struct{ CA, ServerCert, ServerKey, ClientCert, ClientKey string }

func Paths(dir string) PKIPaths {
	return PKIPaths{filepath.Join(dir, "ca.crt"), filepath.Join(dir, "relay.crt"), filepath.Join(dir, "relay.key"), filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")}
}

// GeneratePKI creates a self-contained, private mutual-TLS identity for one
// relay and its invited client. The ephemeral signing key is never persisted.
// For additional users, deploy per-user cert issuance/revocation first.
func GeneratePKI(dir string) (PKIPaths, error) {
	p := Paths(dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return p, err
	}
	// Do not overwrite any existing credential or silently reuse a partial PKI.
	for _, f := range []string{p.CA, p.ServerCert, p.ServerKey, p.ClientCert, p.ClientKey} {
		if _, err := os.Stat(f); err == nil {
			return p, fmt.Errorf("credential already exists: %s", f)
		} else if !errors.Is(err, os.ErrNotExist) {
			return p, err
		}
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return p, err
	}
	caT := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "OpenRoute local test root"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLenZero: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		return p, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return p, err
	}
	if err := writePEM(p.CA, "CERTIFICATE", caDER); err != nil {
		return p, err
	}
	leaf := func(certFile, keyFile, commonName string, usage x509.ExtKeyUsage, dns []string) error {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: commonName}, DNSNames: dns, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(0, 3, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, BasicConstraintsValid: true}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if e != nil {
			return e
		}
		b, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return e
		}
		if e = writePEM(certFile, "CERTIFICATE", der); e != nil {
			return e
		}
		return writePEM(keyFile, "PRIVATE KEY", b)
	}
	if err = leaf(p.ServerCert, p.ServerKey, ServerName, x509.ExtKeyUsageServerAuth, []string{ServerName}); err != nil {
		return p, err
	}
	if err = leaf(p.ClientCert, p.ClientKey, "openroute-invited-client", x509.ExtKeyUsageClientAuth, nil); err != nil {
		return p, err
	}
	return p, nil
}
func serial() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120)); return n }
func writePEM(filename, typ string, der []byte) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func loadCA(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, errors.New("cannot parse CA certificate")
	}
	return p, nil
}
func ClientTLS(dir string) (*tls.Config, error) {
	p := Paths(dir)
	ca, err := loadCA(p.CA)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(p.ClientCert, p.ClientKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: ServerName, RootCAs: ca, Certificates: []tls.Certificate{cert}}, nil
}
func ServerTLS(dir string) (*tls.Config, error) {
	p := Paths(dir)
	ca, err := loadCA(p.CA)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(p.ServerCert, p.ServerKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca, Certificates: []tls.Certificate{cert}}, nil
}
