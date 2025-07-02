package util

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCertStructure(t *testing.T) {

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Logf("Couldn't create ca certificate private key : %s", err)
		t.FailNow()
	}

	now := time.Now()
	then := now.Add(60 * 60 * 24 * 365 * 1000 * 1000 * 1000)

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"Example INC"},
		},
		NotBefore:             now,
		NotAfter:              then,
		SubjectKeyId:          []byte{1},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"*.example.com"},
	}

	intTemplate := caTemplate
	intTemplate.IsCA = false
	intTemplate.SerialNumber = big.NewInt(2)
	intTemplate.DNSNames = []string{"*.sub.example.com"}

	caDer, err := x509.CreateCertificate(nil, &caTemplate, &caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		t.Logf("Couldn't generate certificate (der): %s", err)
		t.FailNow()
	}

	caCert, err := x509.ParseCertificate(caDer)
	if err != nil {
		t.Logf("Couldn't parse certificate: %s", err)
		t.FailNow()
	}

	assert.Equal(t, caCert.IsCA, true)

	intPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Logf("Couldn't create int certificate private key : %s", err)
		t.FailNow()
	}
	assert.GreaterOrEqual(t, intPrivateKey.N.BitLen(), 2048)

	intDer, err := x509.CreateCertificate(nil, &intTemplate, caCert, &intPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		t.Logf("Couldn't generate int certificate (der): %s", err)
		t.FailNow()
	}

	intCert, err := x509.ParseCertificate(intDer)
	if err != nil {
		t.Logf("Couldn't parse certificate : %s", err)
		t.FailNow()
	}

	assert.Equal(t, intCert.IsCA, false)

	assert.Nil(t, intCert.VerifyHostname("test.sub.example.com"), "Couldn't verify hostname.")

	serverTemplate := intTemplate
	serverTemplate.SerialNumber = big.NewInt(3)
	serverTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	serverTemplate.KeyUsage = x509.KeyUsageDigitalSignature
	serverTemplate.DNSNames = []string{"test.sub.example.com"}

	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Logf("Couldn't create int certificate private key : %s", err)
		t.FailNow()
	}

	serverDer, err := x509.CreateCertificate(nil, &serverTemplate, intCert, &serverPrivateKey.PublicKey, intPrivateKey)
	if err != nil {
		t.Logf("Couldn't generate int certificate (der): %s", err)
		t.FailNow()
	}

	serverCert, err := x509.ParseCertificate(serverDer)
	if err != nil {
		t.Logf("Couldn't parse certificate : %s", err)
		t.FailNow()
	}

	assert.Equal(t, serverCert.IsCA, false)

	assert.Nil(t, serverCert.VerifyHostname("test.sub.example.com"), "Couldn't verify hostname.")
	assert.Error(t, serverCert.VerifyHostname("test.non-valid.example.com"))

	serverPEM := new(bytes.Buffer)
	err = pem.Encode(serverPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverDer,
	})
	assert.Nil(t, err, "Failed to pem encode sever private key")

	serverPrivateKeyPEM := new(bytes.Buffer)
	err = pem.Encode(serverPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivateKey),
	})
	assert.Nil(t, err, "Failed to pem encode sever private key")

	assert.Greater(t, serverPEM.Len(), 0, "Buffer empty, couldn't generate server cert pem.")
}
