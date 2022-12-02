package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/cmp"
	"os"
	"strings"
	"time"
)

func main() {
	fmt.Println(cmp.Cmp1999)

	var header cmp.PkiHeader
	header.Pvno = cmp.Cmp2021
	header.FreeText = []string{"aaaaa", "bbbbb", "ccccc"}
	header.SenderNonce = []byte{0, 0, 0, 0, 0}
	header.RecipNonce = []byte{1, 1, 1, 1, 1}

	// sender := pkix.Name{
	//     CommonName:         "example.com",
	//     Country:            []string{"MD"},
	// }
	// header.Sender = sender
	header.Sender = "localhost"
	header.Recipient = "taget-ca.com"

	header.MessageTime = time.Now().UTC()

	// TODO this must be taken dynamically from the CSR itself
	header.ProtectionAlg = pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
	}

	header.SenderKid = []byte{2, 2, 2, 2, 2}
	header.RecipKid = []byte{3, 3, 3, 3, 3}

	header.TransactionId = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	// header.Samba = "haha"
	encoded, _ := asn1.Marshal(header)
	b64encoded := base64.StdEncoding.EncodeToString(encoded)
	// fmt.Println(encoded)
	// fmt.Println(b64encoded)

	pkcs10 := cmp.GenPkcs10Request()
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: pkcs10})

	var message cmp.PkiMessage
	message.Header = header
	message.Body = asn1.RawValue{Class: 0, Tag: 4, IsCompound: true, FullBytes: pkcs10}

	// SerialNumber:       RawValue{Class: 0, Tag: 2, IsCompound: false, Bytes: []uint8{0x0, 0x8c, 0xc3, 0x37, 0x92, 0x10, 0xec, 0x2c, 0x98}, FullBytes: []byte{2, 9, 0x0, 0x8c, 0xc3, 0x37, 0x92, 0x10, 0xec, 0x2c, 0x98}},

	// result := cmp.SendPostRequest(pkcs10)
	// fmt.Println(string(result))

	encoded, _ = asn1.Marshal(message)
	b64encoded = base64.StdEncoding.EncodeToString(encoded)
	// fmt.Println(encoded)
	fmt.Println("Locally constructed PKIMessage:")
	fmt.Println(b64encoded)

	// fmt.Println("Load and parse experiment of a sniffed PKIMessage")
	// canonicPayload := cmp.LoadFile("/home/debdeveu/code/payloads/packet-p10cr-pkimessage.bin")

	// canonicalMessage := new(cmp.PkiMessage)
	// _, _ = asn1.Unmarshal(canonicPayload, canonicalMessage)
	// // fmt.Println(err)
	// // fmt.Println(canonicalMessage.Header.Pvno)
	// fmt.Println(canonicalMessage)

	// template, _ := cmp.CreateCertTemplate("Murzilka")
	// encoded, _ = asn1.Marshal(template)
	// b64encoded = base64.StdEncoding.EncodeToString(encoded)
	// fmt.Println("Simple CertTemplate:")
	// fmt.Println(b64encoded)

	nameComponents := []cmp.Dn{
		{
			Oid:   cmp.Oidify("2.5.4.6"),
			Value: []byte("Germany"),
		},
		{
			Oid:   []int{2, 5, 4, 7},
			Value: []byte("Bayern"),
		},
	}

	subjectName := cmp.CreateSubject(nameComponents)

	template := cmp.CreateCertTemplate(subjectName)
	encoded, _ = asn1.Marshal(template)
	b64encoded = base64.StdEncoding.EncodeToString(encoded)
	fmt.Println("Simple CertTemplate:")
	fmt.Println(b64encoded)

	fmt.Println(cmp.Oidify("1.2.3.4.5"))

	certRequest := cmp.CertRequest{
		CertReqId:    1945,
		CertTemplate: template,
	}
	encoded, _ = asn1.Marshal(certRequest)
	b64encoded = base64.StdEncoding.EncodeToString(encoded)
	fmt.Println("Simple CertRequest:")
	fmt.Println(b64encoded)

	certRequestMessage := cmp.CertReqMessage{
		CertReq: certRequest,
	}
	encoded, _ = asn1.Marshal(certRequestMessage)
	b64encoded = base64.StdEncoding.EncodeToString(encoded)
	fmt.Println("Simple CertRequestMessage:")
	fmt.Println(b64encoded)

	pkiBody := cmp.CreatePkiBodyCr(1945, template)
	encoded, _ = asn1.Marshal(pkiBody)
	b64encoded = base64.StdEncoding.EncodeToString(encoded)
	fmt.Println("Simple PkiBody: ")
	fmt.Println(b64encoded)

	pkiMessage := cmp.CreatePkiMessage(header, pkiBody)
	encoded, _ = asn1.Marshal(pkiMessage)
	b64encoded = base64.StdEncoding.EncodeToString(encoded)
	fmt.Println("Simple PkiMessage: ")
	fmt.Println(b64encoded)

	// This is the b64 contents of raw-cmp-request-ir.bin, which contains an IR PKIMessage
	dataFromFile := `MIICZzCBwQIBAqQCMACkOTA3MREwDwYDVQQDDAhBZG1pbkNBMTEVMBMGA1UECgwMRUpCQ0EgU2Ft
	cGxlMQswCQYDVQQGEwJTRaARGA8yMDEwMDkwODA3MjUwMFqhOjA4BgkqhkiG9n0HQg0wKwQQngNA
	7p504zI55zFUUj6C+DAHBgUrDgMCGgICAfQwCgYIKwYBBQUIAQKiBgQEdXNlcqQSBBAv/E+XD+WO
	9CEk39Gi46oYpRIEEN5PD8sgnWhMIc1RyL4nnCOgggGGMIIBgjCCAX4wgdECAQAwgculJzAlMQ0w
	CwYDVQQDEwR1c2VyMRQwEgYKCZImiZPyLGQBARMEdXNlcqaBnzANBgkqhkiG9w0BAQEFAAOBjQAw
	gYkCgYEA8fFli76QU8rWFNf/RXI8e+tf6EoV7v9hGWU8zByFQDsYqwH9QEdZtUq8mrbZfI1KlN8+
	Z9cxynyDp/wkS0+m8bvUWWZa/vCeTvuy5IAfPAgS11SLDK4iJ0tw12zUm74pqVH+jw0MWz7IG7TR
	zzZgXoTmfbze/BYukSd+s+kWRKsCAwEAAaGBkzANBgkqhkiG9w0BAQUFAAOBgQCNnB7a9bLlOxj5
	ZQdw4+Bt+ZzUed2EwKIPgiHOmVcr5akwCWFEHb2SlsCeSI8f4FkoJN3ZaQ0fpXB1Jl0I+6XOIyFU
	BkWV1dPwBk2B6WwiWM4ByrAjkZQ+sB6ZyrE7gIzc4/V3/5QULeHf4oMBdjkihmmQSEjf2rD0DZH0
	JkxsNDASMBAGCSsGAQUFBwUBAQwDcHdkoBcDFQDCgptN9M86V8FmmA28sWvxBbuwPA==`

	dataFromFile = strings.Replace(dataFromFile, "\r", "", -1)
	dataFromFile = strings.Replace(dataFromFile, "\n", "", -1)
	dataFromFile = strings.Replace(dataFromFile, "\t", "", -1)
	// fmt.Println(dataFromFile)
	exampleRequestIr, _ := base64.StdEncoding.DecodeString(dataFromFile)

	asn1PkiMessage := cmp.ParsePkiMessage(exampleRequestIr)
	fmt.Println(asn1PkiMessage)
	fmt.Println(asn1PkiMessage.Header.MessageTime)
}
