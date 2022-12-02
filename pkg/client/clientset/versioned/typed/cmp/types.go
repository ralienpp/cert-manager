package cmp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Cheatsheet
// ----------
// OctetString	 []byte
// UTF8String	 string
// CHOICE has no direct mapping to Golang, define as asn1.RawValue and parse accordingly.
//		  When serializing, use asn1.MarshalWithParams with `"tag:2,explict"`, to indicate
//		  what goes in (change tag value as necessary)

// General notes
// -------------
// - Use `*big.Int` instead of `int` for certificate serial number fields, because serial
//   numbers can be long, and thus some of them won't fit in an int, leading to parsing failures
// - Structure tag order for ASN1: tag#, optional, omitempty, explicit ...
// - Naming convention follows a Pythonic style when dealing with acronyms, i.e. PkiBody rather
//   than PKIBody

type PkiBodyType int

const (
	Ir       PkiBodyType = iota // [0]  CertReqMessages,            --Initialization Request
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
type PkiStatus = int

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
type CmpVersion = int

const (
	Cmp1999 CmpVersion = 1
	Cmp2000            = 2
	Cmp2021            = 3
)

type PkiFailureInfo asn1.BitString

// type PKIFreeText []asn1.RawValue
type PkiFreeText []string

// Defined in sec5.1. When used, contains bits that protect the PKI message. It is the DER-encoded
// value of ProtectedPart (which consists of PKIHeader and PKIBody).
type PkiProtection = asn1.BitString

type PkiStatusInfo struct {
	Raw asn1.RawContent
	// Status       PKIStatus
	StatusString PkiFreeText    `asn1:"optional,omitempty"`
	FailInfo     asn1.BitString `asn1:"optional,omitempty"`
}

// Defined in sec5.3.17, "actually there is no content since the PKIHeader carries all the required
// information"
// const PKIConfirmContent = asn1.RawValue

type PkiHeader struct {
	Pvno CmpVersion
	// we only support DNSName as sender an receiver for now
	Sender    strDnsName `asn1:"tag:2,optional,omitempty,ia5"`
	Recipient strDnsName `asn1:"tag:2,optional,omitempty,ia5"`

	// -- time of production of this message (used when sender
	// -- believes that the transport will be "suitable"; i.e.,
	// -- that the time will still be meaningful upon receipt)
	MessageTime time.Time `asn1:"tag:0,optional,omitempty,explicit,generalized"`

	// -- algorithm used for calculation of protection bits
	ProtectionAlg pkix.AlgorithmIdentifier `asn1:"tag:1,optional,omitempty,explicit"`

	// -- to identify specific keys used for protection
	SenderKid []byte `asn1:"tag:2,optional,omitempty"`
	RecipKid  []byte `asn1:"tag:3,optional,omitempty"`

	// -- identifies the transaction; i.e., this will be the same in
	// -- corresponding request, response, certConf, and PKIConf messages
	TransactionId []byte `asn1:"tag:4,optional,omitempty,explicit"`

	// -- nonces used to provide replay protection, senderNonce
	// -- is inserted by the creator of this message; recipNonce
	// -- is a nonce previously inserted in a related message by
	// -- the intended recipient of this message
	SenderNonce []byte `asn1:"tag:5,optional,omitempty"`
	RecipNonce  []byte `asn1:"tag:6,optional,omitempty"`

	// -- this may be used to indicate context-specific instructions
	// -- (this field is intended for human consumption)
	FreeText PkiFreeText `asn1:"tag:7,optional,explicit"`

	// -- this may be used to convey context-specific information
	// -- (this field not primarily intended for human consumption)
	GeneralInfo []pkix.AttributeTypeAndValue `asn1:"tag:8,optional,omitempty"`
}

type CertTemplate struct {
	Version      Version                  `asn1:"tag:0,optional,explicit"`
	SerialNumber *big.Int                 `asn1:"tag:1,optional,explicit"`
	SigningAlg   pkix.AlgorithmIdentifier `asn1:"tag:2,optional"`
	Issuer       Name                     `asn1:"tag:3,optional"`
	Validity     OptionalValidity         `asn1:"tag:4,optional,explicit"`
	Subject      Name                     `asn1:"tag:5,optional"`
	PublicKey    SubjectPublicKeyInfo     `asn1:"tag:6,optional,explicit"`
	IssuerUid    UniqueIdentifier         `asn1:"tag:7,optional"`
	SubjectUid   UniqueIdentifier         `asn1:"tag:8,optional,explicit"`
	Extensions   Extensions               `asn1:"tag:9,optional,explicit"`
}

type CertRequest struct {
	CertReqId    int // -- ID for matching request and reply
	CertTemplate CertTemplate

	// These relate to attributes that won't end up in the certificate, but influence the way
	// it is issued.
	// NOTE this is not exposed in the cert-manager API, as far as I understand
	Controls Controls `asn1:"optional,omitempty"` // -- Attributes affecting issuance
}

// See RFC4211 Sec.4
//
//	 CHOICE {
//			raVerified        [0] NULL,
//			signature         [1] POPOSigningKey,
//			keyEncipherment   [2] POPOPrivKey,
//			keyAgreement      [3] POPOPrivKey }
type ProofOfPossession asn1.RawValue

type CertReqMessage struct {
	CertReq CertRequest
	Popo    ProofOfPossession            `asn1:"optional,omitempty"`
	RegInfo []pkix.AttributeTypeAndValue `asn1:"optional,omitempty"`
}

// type PkiBody struct {
// }

// This is used for producing outgoing messages
type PkiMessage struct {
	Header PkiHeader
	Body   asn1.RawValue // This will be set dynamically to a flavor of PKIBody
	// Protection *PKIProtection
	// Extracerts []*CMPCertificate

}

// ///////////////////////// Responses from the CA
type Certificate struct {
	Raw                asn1.RawContent
	TbsCertificate     TbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type EncryptedValue struct {
	Raw         asn1.RawContent
	IntendedAlg pkix.AlgorithmIdentifier `asn1:"tag:0,optional,omitempty,explicit"`
	SymmAlg     pkix.AlgorithmIdentifier `asn1:"tag:1,optional,omitempty,explicit"`
	EncSymmKey  asn1.BitString           `asn1:"tag:2,optional,omitempty,explicit"`
	KeyAlg      pkix.AlgorithmIdentifier `asn1:"tag:3,optional,omitempty,explicit"`
	ValueHint   []byte                   `asn1:"tag:4,optional,omitempty,explicit"`
	EncValue    asn1.BitString
}

type SinglePubInfo struct {
	PubMethod   int
	PubLocation GeneralName `asn1:"optional,omitempty"`
}

type PkiPublicationInfo struct {
	Action   int
	PubInfos []SinglePubInfo `asn1:"optional,omitempty"`
}

type CertifiedKeyPair struct {
	Raw             asn1.RawContent
	CertOrEncCert   CertOrEncCert      `asn1:"tag:0,optional"`
	PrivateKey      EncryptedValue     `asn1:"tag:0,optional,explicit"`
	PublicationInfo PkiPublicationInfo `asn1:"tag:1,optional,explicit"`
}

type CertOrEncCert struct {
	Cert Certificate
}

type CertResponse struct {
	Raw              asn1.RawContent
	CertReqID        int
	Status           PkiStatusInfo
	CertifiedKeyPair CertifiedKeyPair `asn1:"optional"`
	RespInfo         []byte           `asn1:"optional"`
}

type PublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type TbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"tag:0,optional,explicit,default:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           Validity
	Subject            asn1.RawValue
	PublicKey          PublicKeyInfo
	UniqueId           asn1.BitString   `asn1:"tag:1,optional"`
	SubjectUniqueId    asn1.BitString   `asn1:"tag:2,optional"`
	Extensions         []pkix.Extension `asn1:"tag:3,optional,explicit"`
}

type CertRepMessage struct {
	CaPubs    []Certificate `asn1:"tag:1,optional,omitempty"`
	Responses []CertResponse
}
