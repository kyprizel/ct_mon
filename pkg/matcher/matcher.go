package matcher

import (
    "regexp"

    "github.com/google/certificate-transparency/go"
    "github.com/kyprizel/certificate-transparency/go/scanner"
    "github.com/google/certificate-transparency/go/x509"
)


type MatchSubjectRegexUnkCA struct {
    CertificateSubjectRegex    *regexp.Regexp
    PrecertificateSubjectRegex *regexp.Regexp
    CAWhitelist                 map[string]bool
}

// Returns true if either CN or any SAN of |c| matches |CertificateSubjectRegex| and Issuer not in CA whitelist.
func (m MatchSubjectRegexUnkCA) CertificateMatches(c *x509.Certificate) bool {
    if m.CertificateSubjectRegex.FindStringIndex(c.Subject.CommonName) != nil {
        return !m.CAWhitelist[c.Issuer.CommonName]
    }
    for _, alt := range c.DNSNames {
        if m.CertificateSubjectRegex.FindStringIndex(alt) != nil {
            return !m.CAWhitelist[c.Issuer.CommonName]
        }
    }
    return false
}

// Returns true if either CN or any SAN of |p| matches |PrecertificatesubjectRegex| and Issuer is not in CA whitelist.
func (m MatchSubjectRegexUnkCA) PrecertificateMatches(p *ct.Precertificate) bool {
    if m.PrecertificateSubjectRegex.FindStringIndex(p.TBSCertificate.Subject.CommonName) != nil {
        return !m.CAWhitelist[p.TBSCertificate.Issuer.CommonName]
    }
    for _, alt := range p.TBSCertificate.DNSNames {
        if m.PrecertificateSubjectRegex.FindStringIndex(alt) != nil {
            return !m.CAWhitelist[p.TBSCertificate.Issuer.CommonName]
        }
    }
    return false
}


func CreateMatcherFromFlags(MatchSubjectRegex string, CNset map[string]bool) (scanner.Matcher, error) {
    // Make a regex matcher
    var certRegex *regexp.Regexp
    certRegex = regexp.MustCompile(MatchSubjectRegex)

    return MatchSubjectRegexUnkCA{
        CertificateSubjectRegex:    certRegex,
        PrecertificateSubjectRegex: certRegex,
        CAWhitelist: CNset}, nil
}
