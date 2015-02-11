/*Package sslyze parses SSLyze XML data into a similary formed struct.*/
package sslyze

import (
	"encoding/xml"
)

// SSLyzeRun contains all data from a single sslyze scan.
type SSLyzeRun struct {
	SSLyzeVersion string  `xml:"SSLyzeVersion,attr"`
	SSLyzeWeb     string  `xml:"SSLyzeWeb,attr"`
	Title         string  `xml:"title,attr"`
	Results       Results `xml:"results"`
}

// Results contains the results of the sslyze scan
type Results struct {
	DefaultTimeout string   `xml:"defaultTimeout,attr"`
	HTTPSTunnel    string   `xml:"httpsTunnel,attr"`
	StartTLS       string   `xml:"startTLS,attr"`
	TotalScanTime  string   `xml:"totalScanTime,attr"`
	Targets        []Target `xml:"target"`
}

// Target contains all the data from a single target.
type Target struct {
	Host        string      `xml:"host,attr"`
	IP          string      `xml:"ip,attr"`
	Port        string      `xml:"port,attr"`
	CertInfo    CertInfo    `xml:"certinfo"`
	Compression Compression `xml:"compression"`
	ReNeg       ReNeg       `xml:"reneg"`
	ReSum       ReSum       `xml:"resum"`
	SSLv2       SSLCiphers  `xml:"sslv2"`
	SSLv3       SSLCiphers  `xml:"sslv3"`
	TLSv1       SSLCiphers  `xml:"tlsv1"`
	TLSv1_1     SSLCiphers  `xml:"tlsv1_1"`
	TLSv1_2     SSLCiphers  `xml:"tlsv1_2"`
}

// CertInfo contains the target certificate info
type CertInfo struct {
	Argument    string      `xml:"argument,attr"`
	Title       string      `xml:"title,attr"`
	Certificate Certificate `xml:"certificate"`
}

// Certificate contains the target certificate
type Certificate struct {
	MatchingHostName        string        `xml:"hasMatchingHostname,attr"`
	ExtendedValidation      string        `xml:"isExtendedValidation,attr"`
	TrustedByMozillaCAStore string        `xml:"isTrustedByMozillaCAStore,attr"`
	SHA1Fingerprint         string        `xml:"sha1Finderprint,attr"`
	SubjectPublicKeyInfo    PublicKeyInfo `xml:"subjectPublicKeyInfo"`
	Version                 string        `xml:"version"`
	Extensions              []Extension   `xml:"extensions"`
	SignatureValue          string        `xml:"signatureValue"`
	SignatureAlgorithm      string        `xml:"signatureAlgorithm"`
	SerialNumber            string        `xml:"serialNumber"`
	Subject                 Subject       `xml:"subject"`
	Validity                Validity      `xml:"validity"`
	Issuer                  Issuer        `xml:"issuer"`
}

// PublicKeyInfo contains the target public key info
type PublicKeyInfo struct {
	PublicKey          PublicKey `xml:"publicKey"`
	PublicKeyAlgorithm string    `xml:"publicKeyAlgorithm"`
	PublicKeySize      string    `xml:"publicKeySize"`
}

// PublicKey contains the target public key
type PublicKey struct {
	Modulus  string `xml:"modulus"`
	Exponent string `xml:"exponent"`
}

// Extension contains the target's certificate extensions
type Extension struct {
	X509v3SubjectKeyIdentifier   string                         `xml:"X509v3SubjectKeyIdentifier"`
	X509v3ExtendedKeyUsage       X509v3ExtendedKeyUsage         `xml:"X509v3ExtendedKeyUsage"`
	AuthorityInformationAccess   AuthorityInformationAccess     `xml:"AuthorityInformationAccess"`
	X509v3CRLDistributionPoints  []X509v3CRLDistributionPoint   `xml:"X509v3CRLDistributionPoints"`
	X509v3BasicConstraints       string                         `xml:"X509v3BasicConstraints"`
	X509v3KeyUsage               X509v3KeyUsage                 `xml:"X509v3KeyUsage"`
	X509v3SubjectAlternativeName []X509v3SubjectAlternativeName `xml:"X509v3SubjectAlternativeName"`
	X509v3AuthorityKeyIdentifier string                         `xml:"X509v3AuthorityKeyIdentifier"`
	X509v3CertificatePolicies    X509v3CertificatePolicy        `xml:"X509v3CertificatePolicies"`
}

// X509v3ExtendedKeyUsage contains the target's certificate x509 extended key usage settings
type X509v3ExtendedKeyUsage struct {
	TLSWebClientAuthentication string `xml:"TLSWebClientAuthentication"`
	TLSWebServerAuthentication string `xml:"TLSWebServerAuthentication"`
}

// AuthorityInformationAccess contains the target's certificate CA authority information
type AuthorityInformationAccess struct {
	CAIssuers []URI `xml:"CAIssuers"`
	OSCP      []URI `xml:"OSCP"`
}

// URI contains URI list for CAIssuers, OSCP, etc..
type URI struct {
	URI string `xml:"URI"`
}

// X509v3CRLDistributionPoint contains the target's certificate X509 CRL distribution points
type X509v3CRLDistributionPoint struct {
	FullName string `xml:"FullName"`
	URI      string `xml:"URI"`
}

type X509v3KeyUsage struct {
	KeyEncipherment  string `xml:"KeyEncipherment"`
	DigitalSignature string `xml:"DigitalSignature"`
}

// X509v3SubjectAlternativeName contains the target's certificate subject alternative names
type X509v3SubjectAlternativeName struct {
	DNS string `xml:"DNS"`
}

// X509v3CertificatePolicy contains the target's certificate policy information
type X509v3CertificatePolicy struct {
	Policy []string `xml:"Policy"`
	CPS    string   `xml:"CPS"`
}

// Subject contains the target's certificate subject information
type Subject struct {
	OrganizationalUnitName []string `xml:"organizationalUnitName"`
	CommonName             string   `xml:"commonName"`
}

// Validity contains the target's certificate validity
type Validity struct {
	NotAfter  string `xml:"notAfter"`
	NotBefore string `xml:"notBefore"`
}

// Issuer contains the target's certificate issuer information
type Issuer struct {
	CountryName         string `xml:"countryName"`
	CommonName          string `xml:"commonName"`
	OrganizationName    string `xml:"organizationName"`
	LocalityName        string `xml:"localityName"`
	StateOrProvinceName string `xml:"stateOrProvinceName"`
}

// Compression contains the target's support for compression
type Compression struct {
	Supported string `xml:"isSupported,attr"`
}

// ReNeg contains target's support for Session Renegotiation
type ReNeg struct {
	ClientInitiated string `xml:"canBeClientInitiated,attr"`
	Secure          string `xml:"isSecure,attr"`
}

// ReSum contains the target's support for session resume
type ReSum struct {
	ResumptionWithSessionIDs        Resumption `xml:"sessionResumptionWithSessionIDs"`
	SessionResumptionWithTLSTickets Resumption `xml:"sessionResumptionWithTLSTickets"`
}

// Resumption contains the session resumption information
type Resumption struct {
	Error              string   `xml:"error,attr"`
	Errors             string   `xml:"errors,attr"`
	ErrorList          []string `xml:"error"`
	FailedAttempts     string   `xml:"failedAttempts,attr"`
	Supported          string   `xml:"isSupported,attr"`
	SuccessfulAttempts string   `xml:"successfulAttempts,attr"`
	TotalAttempts      string   `xml:"totalAttempts,attr"`
}

// SSLCiphers contains all the target's cipher information
type SSLCiphers struct {
	Exception            string    `xml:"exception,attr"`
	Errors               []Ciphers `xml:"errors>cipherSuite"`
	RejectedCipherSuites []Ciphers `xml:"rejectedCipherSuites>cipherSuite"`
	AcceptedCipherSuites []Ciphers `xml:"acceptedCipherSuites>cipherSuite"`
	PerferredCipherSuite []Ciphers `xml:"preferredCipherSuite>cipherSuite"`
}

// Ciphers contains the individual cipher details
type Ciphers struct {
	ConnectionStatus string `xml:"connectionStatus,attr"`
	Name             string `xml:"name,attr"`
	KeySize          string `xml:"keySize,attr"`
}

// Parse takes a byte array of sslyze xml data and unmarshals it into an
// SSLyzeRun struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func Parse(content []byte) (*SSLyzeRun, error) {
	r := &SSLyzeRun{}
	err := xml.Unmarshal(content, r)
	if err != nil {
		return r, err
	}
	return r, nil
}
