// minimal self-contained example from the RufusJWB fork
// run `go run cmd/cmptest/main.go` to invoke this logic

package main

// import (
// 	"encoding/base64"
// 	"strings"
// )


import (
	"bytes"
	"crypto"
	"crypto/rand"
	x509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"time"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/cmp"
)

func main() {
	senderCommonName := "CloudCA-Integration-Test-User"
	senderDN := cmp.Name{
		[]pkix.AttributeTypeAndValue{
			{Type: cmp.OidCommonName, Value: senderCommonName}}}

	recipientCommonName := "CloudPKI-Integration-Test"
	recipientDN := cmp.Name{
		[]pkix.AttributeTypeAndValue{
			{Type: cmp.OidCommonName, Value: recipientCommonName}}}

	sharedSecret := "SiemensIT"

	url := "https://broker.sdo-qa.siemens.cloud/.well-known/cmp"

	randomTransactionID := createRandom(16)

	randomSenderNonce := createRandom(16)
	randomRecipNonce := createRandom(16)

	csr := `-----BEGIN CERTIFICATE REQUEST-----
MIIEwDCCAqgCAQAwGzEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJYtP4iLdUBt96pl3Exrz/UXzSuTsZ+i
f7cnoFz+DyzS3+6pPLSS7o37g8xxZlqJecY6CfDeLY40maFIsHM4CgkVldwdy4F7
SByFwVZseozGoWGOSSD2ceSMA6qgKmgSRUqwumLJdOJqc5bDQYQqPYabp66hrm9q
VNGlC33XPJ5btITCTwWp+3LNcUYdAPDsMSY/MF8ejExITKjj8M/Xt82vSxY4VNl8
kkSvwmOSSdfzpyl1MN9+zVslUyGJywQyV4vcLqJrM9C32nnh1SY4oE000GTGSbIa
w5kolzrsSBVmLxuNhrgrg4IHZMaYn1OtrI3yVUXuAU0CENHfpUo20CBjTt43ReBo
2HXPoWbxULUOqIDQQELl3ZMOxjt7owXfm5go7EsqMKbPAKtHGuFZkVe/C6JYheWQ
nl0mGC2yfhEix3zviReTmocLLWAeTz3bVO3+jD3aKliv/RA1zyYIwWycAZuVJ17o
e2ceBnHM0/ccO/3giERqHIn+u8hUduCRIo+S1bEB6/Mf91QYFX63uPkYzs4TW/1I
3pklIOiYCbedVORs+U7GMcgPMOa6+oZHYsd2Q/kFly7K0RfhY/g/YTGkLW4LhXSU
/lplOSZEasTrz5az8cdJK4JL8OAfCe6qN6gKMNNhTJC3AYVa0ATbazGvQdkEHCNn
mFr4VRwVfV2zAgMBAAGgYDBeBgkqhkiG9w0BCQ4xUTBPMAwGA1UdEwEB/wQCMAAw
HQYDVR0OBBYEFIa6xq2GOW+R3JVCWZMwTadF7m+2MAsGA1UdDwQEAwIDuDATBgNV
HSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQ0FAAOCAgEAkiXuuU3/dXh3fYX2
agt3JoJ8+GmPSVLvLbwiCkxNnJkI28gpn0BROO+QGUSHRSVaoUM1/GYb1XpXQvDd
LIC5ZC/jlXpC5/PcnvCOQu3YJmEQeDub6YrFcFLMkf1dhOBfEywrEZwfyQ/2tNUZ
FU9yiW0gF015651y8Xl0WMCCi8nsZ19o8MI2zzzafvpyk0M66IYq1GpRM4MzHcnf
YzA4RygZwlrf1fiMjPrzY0oh3U53M1ejGBoAAHSqNJ0rf02FU0U+5M8SaoById8v
ITgegC1Gsga/ox41Leiiinqudije+BX66wze/ZnjKFMfjlg2vBQChzyrTOZ07U2w
T7v8Ey0Go0meB7sjyaKVrJiinI95Woyk/JrvUbTXW6lSVBiTkj+PKQGaGT3otIDo
8HWI35EWs0FoKndUh3MznvsnRycf+7cPoS3prVThmA+bxS1z+pMFwYRFhl63OCQP
kCDAJsS9LESD2wDIrv7Hmxu9SAVwqmil8KMNlwGbBj+MzE9OUUTmL7BQYujVVV8i
MdBk6ysluKbfbolzkPKZxdZHs9YsC3szT8a7U1OY/tABBrF3D6cbEJFZgscuZFgW
LSnod9g7TZsgTN3TY9V6xj6tERl+0/kMTcnQV55UOWAPCQqk0SrwdB9i2ebZCVgQ
1qrQsPB5Gv8K5COmC9b7VY4czB4=
-----END CERTIFICATE REQUEST-----
`
	certificateRequest, _ := pem.Decode([]byte(csr))
	if certificateRequest == nil {
		log.Fatal("failed to decode PEM block containing the CSR")
	}
	parsedCSR, _ := x509.ParseCertificateRequest(certificateRequest.Bytes)
	csrPublicKey := parsedCSR.PublicKey

	randomSalt := createRandom(16)

	p10RequestMessage := cmp.PKIMessage{
		Header: cmp.PKIHeader{
			PVNO:        cmp.CMP2000,
			Sender:      cmp.ChoiceConvert(senderDN, cmp.DirectoryName),
			Recipient:   cmp.ChoiceConvert(recipientDN, cmp.DirectoryName),
			MessageTime: time.Now(),
			ProtectionAlg: cmp.AlgorithmIdentifier{
				Algorithm: cmp.OidPBM,
				Parameters: cmp.PBMParameter{
					Salt: randomSalt,
					OWF: cmp.AlgorithmIdentifier{
						Algorithm:  cmp.OidSHA512,
						Parameters: []byte{},
					},
					IterationCount: 262144,
					MAC: cmp.AlgorithmIdentifier{
						Algorithm:  cmp.OidHMACWithSHA512,
						Parameters: []byte{},
					},
				},
			},
			SenderKID:     cmp.KeyIdentifier(senderDN.String()),
			RecipientKID:  cmp.KeyIdentifier(recipientDN.String()),
			TransactionID: randomTransactionID,
			SenderNonce:   randomSenderNonce,
			RecipNonce:    randomRecipNonce,
		},
		Body: asn1.RawValue{Bytes: certificateRequest.Bytes, IsCompound: true, Class: asn1.ClassContextSpecific, Tag: cmp.PKCS10CertificationRequest},
	}

	responseBody := sendCMPMessage(p10RequestMessage, sharedSecret, url)

	var responseMessage cmp.PKIMessage
	asn1.Unmarshal(responseBody, &responseMessage)

	if !bytes.Equal(responseMessage.Header.TransactionID, randomTransactionID) {
		log.Fatal("TransactionID is not equale")
	}

	if !bytes.Equal(randomSenderNonce, responseMessage.Header.RecipNonce) {
		log.Fatal("Nonce is not equale")
	}

	if responseMessage.Body.Tag != cmp.CertificationResponse {
		log.Fatalf("Response message of type %v", responseMessage.Body.Tag)
	}

	var certRepMessage cmp.CertRepMessage
	asn1.Unmarshal(responseMessage.Body.Bytes, &certRepMessage)

	if len(certRepMessage.Response) != 1 {
		log.Fatalf("Response contained %v certificates", len(certRepMessage.Response))
	}

	if certRepMessage.Response[0].CertifiedKeyPair.CertOrEncCert.Tag != cmp.Certificate {
		log.Fatalf("Response certificate of type %v", certRepMessage.Response[0].CertifiedKeyPair.CertOrEncCert.Tag)
	}

	certificate, _ := x509.ParseCertificate(certRepMessage.Response[0].CertifiedKeyPair.CertOrEncCert.Bytes)

	fmt.Printf("Certificate issued to %v\n", certificate.Subject)
	fmt.Printf("Certificate issued by %v\n", certificate.Issuer)
	fmt.Printf("Certificate valid from %v\n", certificate.NotBefore)
	fmt.Printf("Certificate valid until %v\n", certificate.NotAfter)

	block := &pem.Block{
		Type: "CERTIFICATE",
		Headers: nil,
		Bytes: certificate.Raw,
	}
	pem.Encode(os.Stdout, block)

	if !reflect.DeepEqual(csrPublicKey, certificate.PublicKey) {
		log.Fatalf("Certificate doesn't match to key provided in CSR")
	}

	/*
	   certHash    OCTET STRING,
	   -- the hash of the certificate, using the same hash algorithm
	   -- as is used to create and verify the certificate signature
	*/
	signAlgorithm := certificate.SignatureAlgorithm

	var hashType crypto.Hash

	for _, details := range cmp.SignatureAlgorithmDetails {
		if details.Algo == signAlgorithm {
			hashType = details.Hash
		}
	}

	hashFunc := hashType.New()

	hashFunc.Reset()
	hashFunc.Write(certificate.Raw)
	certHash := hashFunc.Sum(nil)

	randomSenderNonce = createRandom(16)
	randomSalt = createRandom(16)

	certConfMessage := cmp.PKIMessage{
		Header: cmp.PKIHeader{
			PVNO:        cmp.CMP2000,
			Sender:      cmp.ChoiceConvert(senderDN, cmp.DirectoryName),
			Recipient:   cmp.ChoiceConvert(recipientDN, cmp.DirectoryName),
			MessageTime: time.Now(),
			ProtectionAlg: cmp.AlgorithmIdentifier{
				Algorithm: cmp.OidPBM,
				Parameters: cmp.PBMParameter{
					Salt: randomSalt,
					OWF: cmp.AlgorithmIdentifier{
						Algorithm:  cmp.OidSHA512,
						Parameters: []byte{},
					},
					IterationCount: 262144,
					MAC: cmp.AlgorithmIdentifier{
						Algorithm:  cmp.OidHMACWithSHA512,
						Parameters: []byte{},
					},
				},
			},
			SenderKID:     cmp.KeyIdentifier(senderDN.String()),
			RecipientKID:  cmp.KeyIdentifier(recipientDN.String()),
			TransactionID: randomTransactionID,
			SenderNonce:   randomSenderNonce,
			RecipNonce:    responseMessage.Header.SenderNonce,
		},
		Body: cmp.ChoiceConvert(cmp.CertConfirmContent{
			cmp.CertStatus{
				CertHash:  certHash,
				CertReqID: 0,
			},
		}, cmp.CertificateConfirm),
	}

	certConfResponseBody := sendCMPMessage(certConfMessage, sharedSecret, url)

	var certConfResponseMessage cmp.PKIMessage
	asn1.Unmarshal(certConfResponseBody, &certConfResponseMessage)

	if !bytes.Equal(certConfResponseMessage.Header.TransactionID, randomTransactionID) {
		log.Fatal("TransactionID is not equale")
	}

	if !bytes.Equal(randomSenderNonce, certConfResponseMessage.Header.RecipNonce) {
		log.Fatal("Nonce is not equale")
	}

	if certConfResponseMessage.Body.Tag != cmp.Confirmation {
		log.Fatalf("Response message of type %v", responseMessage.Body.Tag)
	}

	fmt.Println("All done!")
}

func sendCMPMessage(requestMessage cmp.PKIMessage, sharedSecret string, url string) (body []byte) {
	requestMessage.Protect(sharedSecret)

	pkiMessageAsDER, err1 := asn1.Marshal(requestMessage)
	if err1 != nil {
		log.Fatalf("Error marshaling structure 1: %v", err1)
	}

	client := &http.Client{}

	resp, err := client.Post(url, "application/pkixcmp", bytes.NewReader(pkiMessageAsDER))
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatalf("Status code %v doesn't equal 200", resp.Status)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	return
}

func createRandom(n int) (randomValue []byte) {
	randomValue = make([]byte, n)
	nRead, err := rand.Read(randomValue)

	if err != nil {
		log.Fatalf("Read err %v", err)
	}
	if nRead != n {
		log.Fatalf("Read returned unexpected n; %d != %d", nRead, n)
	}
	return
}

