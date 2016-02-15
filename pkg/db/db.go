package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"log"
	"time"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/kyprizel/ct_mon/models"
)

type MonDBState struct {
	Id         bson.ObjectId `json:"id,omitempty" bson:"_id"`
	StartIndex int64         `bson:"start_index"`
	Created    time.Time     `bson:"created"`
	Updated    time.Time     `bson:"updated"`
}

type CertInfo struct {
	Id                    bson.ObjectId `json:"id,omitempty" bson:"_id"`
	Index                 int64
	CommonName            string    `bson:"CommonName"`
	Issuer                string    `bson:"Issuer"`
	Serial                string    `bson:"Serial"`
	NotBefore             time.Time `bson:"NotBefore"`
	NotAfter              time.Time `bson:"NotAfter"`
	KeyUsage              int       `bson:"KeyUsage"`
	PublicKeyAlgorithm    int       `bson:"PublicKeyAlgorithm"`
	SignatureAlgorithm    int       `bson:"SignatureAlgorithm"`
	DNSNames              []string  `bson:"DNSNames"`
	EmailAddresses        []string  `bson:"EmailAddresses"`
	OCSPServer            []string  `bson:"OCSPServer"`
	IssuingCertificateURL []string  `bson:"IssuingCertificateURL"`
	PEMCert               string    `bson:"pem"`
	Precert               bool      `bson:"precert"`
	Created               time.Time `bson:"created"`
	SHA256Sum             string    `bson:"sha256_sum"`
}

type MonDB struct {
	uri     string
	session *mgo.Session
}

func Init(uri string) (*MonDB, error) {
	session, err := mgo.Dial(uri)
	if err != nil {
		return nil, err
	}
	m := &MonDB{uri: uri, session: session}
	return m, nil
}

func (m *MonDB) getSession() (*mgo.Session, error) {
	if m.session == nil {
		var err error
		m.session, err = mgo.Dial(m.uri)
		if err != nil {
			return nil, err
		}
	}
	return m.session.Clone(), nil
}

func (m *MonDB) LoadState() (int64, error) {
	session, err := m.getSession()
	if err != nil {
		log.Print("DB connection error\n")
		return 0, err
	}
	col := session.DB("").C("state")

	result := MonDBState{}
	err = col.Find(nil).Sort("-updated").One(&result)
	if err != nil {
		return 0, err
	}

	return result.StartIndex, nil
}

func (m *MonDB) SaveState(StartIndex int64) error {
	session, err := m.getSession()
	if err != nil {
		log.Print("DB connection error\n")
		return err
	}

	col := session.DB("").C("state")
	var needInsert bool
	state := MonDBState{}
	err = col.Find(nil).Sort("-updated").One(&state)
	if err != nil {
		needInsert = true
	}

	if !needInsert {
		qs := bson.M{"_id": state.Id}
		change := bson.M{"$set": bson.M{"start_index": StartIndex, "updated": time.Now().UTC()}}
		return col.Update(qs, change)
	}

	state.Id = bson.NewObjectId()
	state.StartIndex = StartIndex
	state.Created = time.Now().UTC()
	state.Updated = state.Created
	return col.Insert(state)
}

func (m *MonDB) StoreCertDetails(cert *CertInfo) error {
	session, err := m.getSession()
	if err != nil {
		log.Print("DB connection error\n")
		return err
	}

	col := session.DB("").C("certificate_details")
	/* do not store same entry more than once */
	var cnt int
	cnt, err = col.Count(bson.M{"index": cert.Index})
	if cnt < 1 {
		cert.Id = bson.NewObjectId()
		cert.Created = time.Now().UTC()
		return col.Insert(cert)
	}
	return nil;
}

type CertHandler struct {
	DB *MonDB
}

func (s *CertHandler) HandleEvents(ch chan models.MonEvent) {
	for {
		ev := <-ch
		entry := *ev.LogEntry
		switch ev.Type {
		case models.CT_CERT:
			pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: entry.X509Cert.Raw})
			hasher := sha256.New()
			hasher.Write(entry.X509Cert.Raw)
			sha := hex.EncodeToString(hasher.Sum(nil))
			c := &CertInfo{Index: entry.Index, CommonName: entry.X509Cert.Subject.CommonName,
				Issuer:    entry.X509Cert.Issuer.CommonName,
				Serial:    entry.X509Cert.SerialNumber.String(),
				NotBefore: entry.X509Cert.NotBefore, NotAfter: entry.X509Cert.NotAfter,
				KeyUsage:           int(entry.X509Cert.KeyUsage),
				PublicKeyAlgorithm: int(entry.X509Cert.PublicKeyAlgorithm),
				SignatureAlgorithm: int(entry.X509Cert.SignatureAlgorithm),
				DNSNames:           entry.X509Cert.DNSNames, EmailAddresses: entry.X509Cert.EmailAddresses,
				OCSPServer:            entry.X509Cert.OCSPServer,
				IssuingCertificateURL: entry.X509Cert.IssuingCertificateURL,
				PEMCert:               string(pemCert), Precert: false, SHA256Sum: sha}
			s.DB.StoreCertDetails(c)
		case models.CT_PRECERT:
			pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: entry.Precert.TBSCertificate.Raw})
			hasher := sha256.New()
			hasher.Write(entry.Precert.TBSCertificate.Raw)
			sha := hex.EncodeToString(hasher.Sum(nil))
			c := &CertInfo{Index: entry.Index, CommonName: entry.Precert.TBSCertificate.Subject.CommonName,
				Issuer:                entry.Precert.TBSCertificate.Issuer.CommonName,
				Serial:                entry.Precert.TBSCertificate.SerialNumber.String(),
				NotBefore:             entry.Precert.TBSCertificate.NotBefore,
				NotAfter:              entry.Precert.TBSCertificate.NotAfter,
				KeyUsage:              int(entry.Precert.TBSCertificate.KeyUsage),
				PublicKeyAlgorithm:    int(entry.Precert.TBSCertificate.PublicKeyAlgorithm),
				SignatureAlgorithm:    int(entry.Precert.TBSCertificate.SignatureAlgorithm),
				DNSNames:              entry.Precert.TBSCertificate.DNSNames,
				EmailAddresses:        entry.Precert.TBSCertificate.EmailAddresses,
				OCSPServer:            entry.Precert.TBSCertificate.OCSPServer,
				IssuingCertificateURL: entry.Precert.TBSCertificate.IssuingCertificateURL,
				PEMCert:               string(pemCert), Precert: true, SHA256Sum: sha}
			s.DB.StoreCertDetails(c)
		case models.CT_QUIT:
			break
		}
	}
}
