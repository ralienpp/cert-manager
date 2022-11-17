package cmp

import "encoding/asn1"
import "time"
import "crypto/x509/pkix"

// Cheatsheet
// OctetString	 []byte
// UTF8String	 string

type strDnsName string

type PKIBodyType int8

const (
	Ir       PKIBodyType = iota // [0]  CertReqMessages,            --Initialization Request
	Ip                          // [1]  CertRepMessage,             --Initialization Response
	Cr                          // [2]  CertReqMessages,            --Certification Request
	Pp                          // [3]  CertRepMessage,             --Certification Response
	P10cr                       // [4]  CertificationRequest,       --imported from // [PKCS10]
	Popdecc                     // [5]  POPODecKeyChallContent,     --pop Challenge
	Popdecr                     // [6]  POPODecKeyRespContent,      --pop Response
	Kur                         // [7]  CertReqMessages,            --Key Update Request
	Kup                         // [8]  CertRepMessage,             --Key Update Response
	Krr                         // [9]  CertReqMessages,            --Key Recovery Request
	Krp                         // [10] KeyRecRepContent,           --Key Recovery Response
	Rr                          // [11] RevReqContent,              --Revocation Request
	Rp                          // [12] RevRepContent,              --Revocation Response
	Ccr                         // [13] CertReqMessages,            --Cross-Cert. Request
	Ccp                         // [14] CertRepMessage,             --Cross-Cert. Response
	Ckuann                      // [15] CAKeyUpdAnnContent,         --CA Key Update Ann.
	Cann                        // [16] CertAnnContent,             --Certificate Ann.
	Rann                        // [17] RevAnnContent,              --Revocation Ann.
	Crlann                      // [18] CRLAnnContent,              --CRL Announcement
	Pkiconf                     // [19] PKIConfirmContent,          --Confirmation
	Nested                      // [20] NestedMessageContent,       --Nested Message
	Genm                        // [21] GenMsgContent,              --General Message
	Genp                        // [22] GenRepContent,              --General Response
	Error                       // [23] ErrorMsgContent,            --Error Message
	CertConf                    // [24] CertConfirmContent,         --Certificate confirm
	PollReq                     // [25] PollReqContent,             --Polling request
	PollRep                     // [26] PollRepContent              --Polling response
)

// PKIStatus defined in sec5.2.3.
type PkiStatus = int8

const (
	Accepted               PkiStatus = iota // (0) you got exactly what you asked for
	GrantedWithMods                         // (1) you got something like what you asked for
	Rejection                               // (2) you don't get it, more information elsewhere in the message
	Waiting                                 // (3) the request body part has not yet been processed
	RevocationWarning                       // (4) this message contains a warning that a revocation is imminent
	RevocationNotification                  // (5) notification that a revocation has occurred
	KeyUpdateWarning                        // (6) update already done for the oldCertId specified in CertReqMsg
)

// protocol version
type CmpVersion = int8

const (
	Cmp1999 CmpVersion = 1
	Cmp2000            = 2
	Cmp2021            = 3
)

// type PKIFreeText []asn1.RawValue
type PKIFreeText []string
type PKIHeader struct {
	Pvno CmpVersion
	// we only support DNSName as sender an receiver for now
	Sender    strDnsName `asn1:"tag:2,ia5,optional,omitempty"`
	Recipient strDnsName `asn1:"tag:2,ia5,optional,omitempty"`

	// -- time of production of this message (used when sender
	// -- believes that the transport will be "suitable"; i.e.,
	// -- that the time will still be meaningful upon receipt)
	MessageTime time.Time `asn1:"generalized,explicit,optional,tag:0,omitempty"`
	
	// -- algorithm used for calculation of protection bits
	ProtectionAlg pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:1,omitempty"`

	// -- to identify specific keys used for protection
	SenderKID []byte `asn1:"optional,tag:2,omitempty"`
	RecipKID  []byte `asn1:"optional,tag:3,omitempty"`

	// -- identifies the transaction; i.e., this will be the same in
	// -- corresponding request, response, certConf, and PKIConf messages
	TransactionID []byte `asn1:"optional,explicit,tag:4,omitempty"`

	// -- nonces used to provide replay protection, senderNonce
	// -- is inserted by the creator of this message; recipNonce
	// -- is a nonce previously inserted in a related message by
	// -- the intended recipient of this message
	SenderNonce []byte `asn1:"optional,tag:5,omitempty"`
	RecipNonce  []byte `asn1:"optional,tag:6,omitempty"`

	// -- this may be used to indicate context-specific instructions
	// -- (this field is intended for human consumption)
	FreeText PKIFreeText `asn1:"optional,explicit,tag:7"`

	// -- this may be used to convey context-specific information
	// -- (this field not primarily intended for human consumption)
	GeneralInfo []pkix.AttributeTypeAndValue `asn1:"optional,tag:8,omitempty"`
}

