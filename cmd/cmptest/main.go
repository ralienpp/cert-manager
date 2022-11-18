package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/cmp"
    "os"
	"time"
)

func main() {
	fmt.Println(cmp.Cmp1999)

	var header cmp.PKIHeader
	header.Pvno = cmp.Cmp2021
	header.FreeText = []string{"aaaaa", "bbbbb", "ccccc"}
	header.SenderNonce = []byte{0,0,0,0,0}
	header.RecipNonce = []byte{1,1,1,1,1}

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
		Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
	}


	header.SenderKID = []byte{2,2,2,2,2}
	header.RecipKID = []byte{3,3,3,3,3}


	header.TransactionID = []byte{1,2,3,4,5,6,7,8,9,10}


	// header.Samba = "haha"
	encoded, _ := asn1.Marshal(header)
	b64encoded := base64.StdEncoding.EncodeToString(encoded)
	fmt.Println(encoded)
	fmt.Println(b64encoded)

	pkcs10 := cmp.GenPkcs10Request()
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: pkcs10})

}
