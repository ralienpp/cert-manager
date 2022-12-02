/*
Various primitive ASN1 types used indirectly by PKIMessage are defined here.
*/

package cmp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
)

type CountryName struct {
	X121DccCode       string `asn1:"optional,omitempty"`
	Iso3166Alpha2Code string `asn1:"optional,omitempty"`
}

type AdministrationDomainName string

type NetworkAddress string
type TerminalIdentifier string
type PrivateDomainName string
type OrganizationName string
type NumericUserIdentifier string

type strDnsName string

type Name struct {
	RdnSequence pkix.RDNSequence
}

type PersonalName struct {
	SurName             string `asn1:"tag:0"`
	GivenName           string `asn1:"tag:1,optional"`
	Initials            string `asn1:"tag:2,optional"`
	GenerationQualifier string `asn1:"tag:3,optional"`
}

type GeneralName struct {
	Raw                       asn1.RawContent
	OtherName                 *AnotherName          `asn1:"tag:0,optional,omitempty"`
	Rfc822Name                *string               `asn1:"tag:1,optional,omitempty,ia5"`
	DnsName                   *string               `asn1:"tag:2,optional,omitempty,ia5"`
	X400Address               *OrAddress            `asn1:"tag:3,optional,omitempty"`
	DirectoryName             Name                  `asn1:"tag:4,optional,omitempty"`
	EdiPartyName              *EdiPartyName         `asn1:"tag:5,optional,omitempty"`
	UniformResourceIdentifier string                `asn1:"tag:6,optional,omitempty,ia5"`
	IpAddress                 []byte                `asn1:"tag:7,optional,omitempty"`
	RegisteredId              asn1.ObjectIdentifier `asn1:"tag:8,optional,omitempty"`
}

type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type AnotherName struct {
	TypeId asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"tag:0,optional,explicit"`
}

type DirectoryString string

type BuiltInStandardAttributes struct {
	CountryName             *CountryName              `asn1:"optional,omitempty"`
	AdminitrationDomainName *AdministrationDomainName `asn1:"tag:2,optional,omitempty,application"`
	NetworkAddress          *NetworkAddress           `asn1:"tag:0,optional,omitempty"`
	TerminalIdentifier      *TerminalIdentifier       `asn1:"tag:1,optional,omitempty"`
	PrivateDomainName       *PrivateDomainName        `asn1:"tag:2,optional,omitempty,explicit"`
	OrganizationName        *OrganizationName         `asn1:"tag:3,optional,omitempty"`
	NumericUserIdentifier   *NumericUserIdentifier    `asn1:"tag:4,optional,omitempty"`
	PersonalName            *PersonalName             `asn1:"tag:5,optional,omitempty,set"`
	OrganizationalUnitNames *OrganizationalUnitNames  `asn1:"tag:6,optional,omitempty"`
}

type OrAddress struct {
	StandardAttrs      *BuiltInStandardAttributes
	DomainDefinedAttrs *BuiltInDomainDefinedAttributes `asn1:"optional,omitempty"`
	ExtensionAttris    *ExtensionAttributes            `asn1:"optional,omitempty,set"`
}

type EdiPartyName struct {
	NameAssigner string `asn1:"tag:0,optional"`
	PartyName    DirectoryString
}

type Dn struct {
	Oid      asn1.ObjectIdentifier
	Name     string
	Code     string
	Critical bool
	Value    []byte
}

type BuiltInDomainDefinedAttribute struct {
	Type  string
	Value string
}

type BuiltInDomainDefinedAttributes []BuiltInDomainDefinedAttribute

type OrganizationalUnitNames []string

type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type UniqueIdentifier = asn1.BitString

type Extensions []pkix.Extension

type Version int

// As defined in RFC4211, NOTE: at least one MUST be present!
type OptionalValidity struct {
	NotBefore time.Time `asn1:"tag:0,generalized,explicit"`
	NotAfter  time.Time `asn1:"tag:1,generalized,explicit"`
}

type ExtensionAttribute struct {
	Type  int           `asn1:"tag:0"`
	Value asn1.RawValue `asn1:"tag:1"`
}

type ExtensionAttributes []ExtensionAttribute

type Controls []pkix.AttributeTypeAndValue
