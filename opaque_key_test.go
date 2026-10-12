package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"
)

// opaqueKey hides the concrete key type, like a PKCS#11 (HSM) key that only
// exposes crypto.Signer and crypto.Decrypter.
type opaqueKey struct{ k crypto.Signer }

func (o opaqueKey) Public() crypto.PublicKey { return o.k.Public() }
func (o opaqueKey) Sign(r io.Reader, d []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.k.Sign(r, d, opts)
}
func (o opaqueKey) Decrypt(r io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return o.k.(crypto.Decrypter).Decrypt(r, msg, opts)
}

func opaqueTestCert(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "opaque"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestDecryptWithOpaqueRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := opaqueTestCert(t, key)
	content := []byte("hello from an HSM")
	der, err := Encrypt(content, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p7.Decrypt(cert, opaqueKey{key})
	if err != nil {
		t.Fatalf("Decrypt with an opaque RSA key: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("got %q, want %q", got, content)
	}
}

func TestSignWithOpaqueKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"rsa": rsaKey, "ecdsa": ecKey} {
		t.Run(name, func(t *testing.T) {
			cert := opaqueTestCert(t, key)
			sd, err := NewSignedData([]byte("signed by an opaque key"))
			if err != nil {
				t.Fatal(err)
			}
			sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
			if err := sd.AddSigner(cert, opaqueKey{key}, SignerInfoConfig{}); err != nil {
				t.Fatalf("AddSigner with an opaque %s key: %v", name, err)
			}
			der, err := sd.Finish()
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := p7.Verify(); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// A degenerate certs-only SignedData (no content, no signers) parses.
func TestParseDegenerateCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := opaqueTestCert(t, key)
	der, err := DegenerateCertificate(cert.Raw)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p7.Certificates) != 1 || !p7.Certificates[0].Equal(cert) {
		t.Fatalf("got %d certificates", len(p7.Certificates))
	}
	if len(p7.Content) != 0 {
		t.Fatalf("unexpected content %x", p7.Content)
	}
}
