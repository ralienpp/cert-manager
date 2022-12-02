package cmp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	// "crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	// "io/ioutil"
	"encoding/asn1"
	"fmt"
)

type ClientInterface interface {
	GetCertificate(*x509.Certificate, *x509.Certificate, crypto.PublicKey, interface{}) ([]byte, *x509.Certificate, error)
}

type Client struct {
	server string
}

func New(server string) ClientInterface {
	fmt.Println("## Initialized server", server)
	return &Client{
		server: server,
	}
}

// func (c *Client) GetCertificate(template *x509.Certificate, issuerCert *x509.Certificate, publicKey crypto.PublicKey, signerKey interface{}) ([]byte, *x509.Certificate, error) {
// 	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, publicKey, signerKey)

// 	if err != nil {
// 		return nil, nil, fmt.Errorf("error creating x509 certificate: %s", err.Error())
// 	}

// 	cert, err := x509.ParseCertificate(derBytes)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("error decoding DER certificate bytes: %s", err.Error())
// 	}

// 	pemBytes := bytes.NewBuffer([]byte{})
// 	err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("error encoding certificate PEM: %s", err.Error())
// 	}

// 	return pemBytes.Bytes(), cert, err
// }

func (c *Client) GetCertificate(template *x509.Certificate, issuerCert *x509.Certificate, publicKey crypto.PublicKey, signerKey interface{}) ([]byte, *x509.Certificate, error) {

	fmt.Println("Serializing ...")
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: template.Raw})
	// template.Subject := pkix.Name{
	// 	Organization:  []string{"Zubrique"},
	// 	Country:       []string{"US"},
	// 	Province:      []string{""},
	// 	Locality:      []string{"San Francisco"},
	// 	StreetAddress: []string{"Golden Gate Bridge"},
	// 	PostalCode:    []string{"94016"},
	// }
	fmt.Println("Here template >>>>>>", base64.StdEncoding.EncodeToString(pemCert))
	fmt.Println("SubjectName: ", template.Subject)
	fmt.Println("Raw template  >>>>>>", base64.StdEncoding.EncodeToString(template.RawTBSCertificate))

	pemCertIssuer := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerCert.Raw})
	fmt.Println("Here issuer   >>>>>>", base64.StdEncoding.EncodeToString(pemCertIssuer))
	fmt.Println("Done!~~~~~~~~~~")

	tbsCertContents, _ := asn1.Marshal(template)
	fmt.Println("JVOMPIHA    ", base64.StdEncoding.EncodeToString(tbsCertContents))

	// ioutil.WriteFile("/tmp/out.pem", pemCert, 0644)

	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, publicKey, signerKey)

	if err != nil {
		return nil, nil, fmt.Errorf("error creating x509 certificate: %s", err.Error())
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding DER certificate bytes: %s", err.Error())
	}

	pemBytes := bytes.NewBuffer([]byte{})
	err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding certificate PEM: %s", err.Error())
	}

	fmt.Println("RESULT FINAL           ", base64.StdEncoding.EncodeToString(pemBytes.Bytes()))
	return pemBytes.Bytes(), cert, err
}
