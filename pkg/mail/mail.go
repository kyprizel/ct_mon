package mail

import (
    "log"
    "fmt"
    "bytes"
    "strings"
    "crypto/sha256"
    "encoding/pem"
    "encoding/hex"

    "html/template"
    "net/smtp"

    "github.com/kyprizel/ct_mon/models"
)

const mail_tpl = `From: {{ .From }}
To: {{ .To }}
Subject: {{ .Subject }}
MIME-version: 1.0
Content-Type: multipart/alternative; boundary="===============7660463594043036259==

--===============7660463594043036259==
Content-Type: text/plain
MIME-Version: 1.0
Content-Transfer-Encoding: 8bit

New certificate found1

Log Index: {{ .Index }}
SHA256:</b> {{ .Hashsum }}
CN: {{ .CN }}
Issuer: {{ .Issuer }}
Details: https://crt.sh/?sha256={{ .Hashsum }}

SANs:
    {{range .SAN}}
    {{ . }}
    {{end}}

{{ .Pem }}


--===============7660463594043036259==
Content-Type: text/html; charset="UTF-8"
MIME-Version: 1.0
Content-Transfer-Encoding: 8bit

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Certificate Transparency notification</title>
    </head>
    <body>
        <div>
        <h2>New certificate found</h2>
        <table>
         <tr><th>Log Index:</th><td>{{ .Index }}</td></tr>
         <tr><th>SHA256:</th><td>{{ .Hashsum }}</td></tr>
         <tr><th>CN:</th><td>{{ .CN }}</td></tr>
         <tr><th>Issuer:</th><td>{{ .Issuer }}</td></tr>
         <tr><th align="left"><a href="https://crt.sh/?sha256={{ .Hashsum }}">View details</a></th><td></td></tr>
         <tr><th align="left">SANs:</th><td></td></tr>
         <tr>
            <td colspan="2" align="left">
            <ol>{{range .SAN}}<li>{{ . }}</li>{{end}}</ol>
            </td>
        </tr>
        <tr>
        <td colspan="2">
        <pre>
        {{ .Pem }}
        </pre>
        </td>
        </tr>
    </body>
</html>


--===============7660463594043036259==--
`

type CertHandler struct {
    Emails  []string
    Host    string
    Port    int
    User    string
    Password  string
    From    string
    Subj    string
}

func (s *CertHandler) HandleEvents(ch chan models.MonEvent) {
    for {
        ev := <- ch
        entry := *ev.LogEntry
        switch ev.Type {
            case models.CT_CERT:
                pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: entry.X509Cert.Raw})
                hasher := sha256.New()
                hasher.Write(entry.X509Cert.Raw)
                sha := hex.EncodeToString(hasher.Sum(nil))
                t, _ := template.New("notification").Parse(mail_tpl)
                data := struct {
                    From string
                    Subject string
                    To string
                    Index int64
                    CN string
                    SAN []string
                    Issuer string
                    Pem string
                    Hashsum string
                }{
                    From: s.From,
                    To: strings.Join([]string(s.Emails), ","),
                    Subject: s.Subj,
                    Index: entry.Index,
                    CN: entry.X509Cert.Subject.CommonName,
                    SAN: entry.X509Cert.DNSNames,
                    Issuer: entry.X509Cert.Issuer.CommonName,
                    Pem: string(pemCert),
                    Hashsum: sha,
                }
                buf := new(bytes.Buffer)
                t.Execute(buf, data)

                var auth smtp.Auth
                if (s.User != "" && s.Password != "") {
                    auth = smtp.PlainAuth("", s.User, s.Password, s.Host)
                }

                /* XXX: handle errors */
                err := smtp.SendMail(fmt.Sprintf("%s:%d", s.Host, s.Port), auth, s.From, s.Emails, buf.Bytes())
                if err != nil {
                    log.Print("Error sending email")
                }
            case models.CT_PRECERT:
                pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: entry.Precert.TBSCertificate.Raw})
                hasher := sha256.New()
                hasher.Write(entry.Precert.TBSCertificate.Raw)
                sha := hex.EncodeToString(hasher.Sum(nil))
                t, _ := template.New("notification").Parse(mail_tpl)
                data := struct {
                    From string
                    Subject string
                    To string
                    Index int64
                    CN string
                    SAN []string
                    Issuer string
                    Pem string
                    Hashsum string
                }{
                    From: s.From,
                    To: strings.Join([]string(s.Emails), ","),
                    Subject: s.Subj,
                    Index: entry.Index,
                    CN: entry.Precert.TBSCertificate.Subject.CommonName,
                    SAN: entry.Precert.TBSCertificate.DNSNames,
                    Issuer: entry.Precert.TBSCertificate.Issuer.CommonName,
                    Pem: string(pemCert),
                    Hashsum: sha,
                }
                buf := new(bytes.Buffer)
                t.Execute(buf, data)

                var auth smtp.Auth
                if (s.User != "" && s.Password != "") {
                    auth = smtp.PlainAuth("", s.User, s.Password, s.Host)
                }

                /* XXX: handle errors */
                err := smtp.SendMail(fmt.Sprintf("%s:%d", s.Host, s.Port), auth, s.From, s.Emails, buf.Bytes())
                if err != nil {
                    log.Print("Error sending email")
                }
            case models.CT_QUIT:
                break
        }
    }
}
