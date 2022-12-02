package cmp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http"
	"os"
	"strconv"
	"strings"
	"fmt"
)

// Load the contents of a file at a given path and return it as an array
// of bytes
func LoadFile(path string) []byte {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return content
}

// Create a simplified CertTemplate structure, as defined in RFC4211; note that not all functionality
// defined in the RFC is supported
// func CreateCertTemplate(subjectName string) (*x509.Certificate, error) {

// 	tmpl := x509.Certificate{
// 		// The CA will set its own serial number, though
// 		// SerialNumber:          serialNumber,
// 		Subject:               pkix.Name{CommonName: subjectName},
// 		// Subject:               pkix.Name{Organization: []string{subjectName}},
// 		SignatureAlgorithm:    x509.SHA256WithRSA,
// 		// time-related attributes are skipped, the CA will override them
// 		// NotBefore:             time.Now(),
// 		// NotAfter:              time.Now().Add(time.Hour * 24 * 30 * 12), // 1 year
// 		// BasicConstraintsValid: true,
// 	}
// 	return &tmpl, nil
// }

func CreateCertTemplate(subjectName pkix.RDNSequence) CertTemplate {
	result := CertTemplate{}
	result.Subject = Name{subjectName}
	// result.Subject = pkix.Name{CommonName: subjectName}
	// // subjectName := pkix.Name{CommonName: subjectName}

	// publicKey := SubjectPublicKeyInfo{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}}
	// // type SubjectPublicKeyInfo struct {
	// // 	Algorithm        pkix.AlgorithmIdentifier
	// // 	SubjectPublicKey asn1.BitString
	// // }
	// result.PublicKey = publicKey

	return result

}

// Send a binary payload to a HTTP server and return the server's response body
func SendPostRequest(payload []byte) []byte {
	resp, err := http.Post("https://gobyexample.com", "application/pkixcmp", bytes.NewReader(payload))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	buf := &bytes.Buffer{}
	buf.ReadFrom(resp.Body)

	return buf.Bytes()

}

// Generate a PKCS10 certificate signing request and return the raw ASN.1-encoded
// data
func GenPkcs10Request() []byte {
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 1024)

	emailAddress := "test@example.com"
	subj := pkix.Name{
		CommonName:         "example.com",
		Country:            []string{"DE"},
		Province:           []string{"Bayern"},
		Locality:           []string{"Muenchen"},
		Organization:       []string{"Feldmoching"},
		OrganizationalUnit: []string{"Landwirtschaft IT Sicherheit"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(emailAddress),
				},
			},
		},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	return csrBytes

}

func GenCrmfRequest() []byte {
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 1024)

	emailAddress := "test@example.com"
	subj := pkix.Name{
		CommonName:         "example.com",
		Country:            []string{"DE"},
		Province:           []string{"Bayern"},
		Locality:           []string{"Muenchen"},
		Organization:       []string{"Feldmoching"},
		OrganizationalUnit: []string{"Landwirtschaft IT Sicherheit"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(emailAddress),
				},
			},
		},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	return csrBytes

}

// Assemble and return a Subject made if distinguishedName elements
func CreateSubject(items []Dn) pkix.RDNSequence {
	result := make(pkix.RDNSequence, 0)

	for _, item := range items {
		set := make([]pkix.AttributeTypeAndValue, 0)
		av := pkix.AttributeTypeAndValue{
			Type:  item.Oid,
			Value: string(item.Value),
		}
		set = append(set, av)
		result = append(result, set)
	}

	return result
}

// Will return an asn1.RawValue if all is well
func CreatePkiBodyCr(requestId int, template CertTemplate) asn1.RawValue {
	// func CreatePkiBodyCr(requestId int, template CertTemplate) (any, error) {
	certRequest := CertRequest{
		CertReqId:    requestId,
		CertTemplate: template,
	}

	certRequestMessage := CertReqMessage{
		CertReq: certRequest,
	}

	result, _ := asn1.MarshalWithParams(certRequestMessage, "tag:2,explict") //2 is Cr
	// if err != nil {
	// return nil, err
	// }
	return asn1.RawValue{FullBytes: result}
	// return asn1.RawValue{FullBytes: result}, nil

}

func CreatePkiMessage(header PkiHeader, body asn1.RawValue) PkiMessage {
	result := PkiMessage{
		Header: header,
		Body:   body,
	}

	return result

}

// function SetChoice(structure any, tag int, params string) {

// 	format := fmt.Sprintf("tag:%s")

// 	return asn1.MarshalWithParams
// }

// Transform a string OID into a numeric array representation, suitable for
// lower-level serialization functions, Example: "2.5.4.6" -> []int{2, 5, 4, 6}
func Oidify(raw string) []int {
	parts := strings.Split(raw, ".")
	result := make([]int, len(parts))

	for index, item := range parts {
		number, _ := strconv.Atoi(item)
		result[index] = number
	}
	return result
}

func ParsePkiMessage(raw []byte) PkiMessage {
	result := PkiMessage{}

	_, err := asn1.Unmarshal(raw, &result)
	if err != nil {
		panic(err)
	}

	messageType := PkiBodyType(result.Body.FullBytes[2])

	switch messageType {
	// case Ip, Pp, Kup, Ccp:
	case Ip:
		// This is a [1]  CertRepMessage, i.e. a response to an IR certificate request
		fmt.Println("This is a supported message")

		body := CertRepMessage{}
		//////////// TODO here the parser fails
		// set breakpoint
		boba, rebaerror := asn1.Unmarshal(result.Body.Bytes, &body)
		fmt.Println(boba)
		fmt.Println(rebaerror)
		// result.Body = body
		fmt.Println(body)
		


	default:
		panic(fmt.Sprintf("Unsupported PKIMessage type %d", messageType))
	}

	return result
}
