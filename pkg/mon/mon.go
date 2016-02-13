package mon

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"time"

	"golang.org/x/net/context"

	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
	"github.com/kyprizel/certificate-transparency/go/scanner"

	"github.com/kyprizel/ct_mon/pkg/matcher"

	"github.com/kyprizel/ct_mon/models"
	"github.com/kyprizel/ct_mon/pkg/db"
	"github.com/kyprizel/ct_mon/pkg/mail"
)

type MonConfig struct {
	LogUri            string   `json:"log_uri"`
	MatchSubjectRegex string   `json:"match_subject_regex"`
	BatchSize         int      `json:"batch_size"`
	NumWorkers        int      `json:"num_workers"`
	ParallelFetch     int      `json:"parallel_fetch"`
	MongoURI          string   `json:"mongo_uri"`
	StoreMatches      bool     `json:"store_matches"`
	Emails            []string `json:"notify_persons"`
	SMTPHost          string   `json:"smtp_host"`
	SMTPPort          int      `json:"smtp_port"`
	SMTPUser          string   `json:"smtp_user"`
	SMTPPasswd        string   `json:"smtp_password"`
	SMTPSubj          string   `json:"smtp_subject"`
	SMTPFrom          string   `json:"smtp_from"`
	NotifyMatches     bool     `json:"notify_on_match"`
	StartIndex        int64    `json:"start_index"`
	CAWhitelist       []string `json:"ca_whitelist"`
	Verbose           bool     `json:"verbose"`
	TickTime          int      `json:"save_state"`
	RescanPeriod      int      `json:"rescan_period"`
}

type MonCtx struct {
	StartIndex int64
	Handlers   []chan models.MonEvent
	conf       *MonConfig
	db         *db.MonDB
}

func New() (*MonCtx, error) {
	c := &MonCtx{}
	return c, nil
}

func (ctx *MonCtx) SetConfig(fileName string, verbose bool) error {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	var conf MonConfig
	err = json.Unmarshal(file, &conf)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	var isBadSMTPConf bool
	var isBadDBConf bool

	if conf.LogUri == "" {
		conf.LogUri = "http://ct.googleapis.com/aviator"
	}

	if conf.MatchSubjectRegex == "" {
		log.Fatal("Invalid monitoring regexp, use .* to match everything (a lot!)")
		return nil
	}

	if conf.BatchSize == 0 {
		conf.BatchSize = 1000
	}

	if conf.NumWorkers == 0 {
		conf.NumWorkers = 2
	}

	if conf.ParallelFetch == 0 {
		conf.ParallelFetch = 2
	}

	if conf.Emails == nil {
		log.Println("No notification emails cofigured, notifications will not be sent")
		isBadSMTPConf = true
	}

	if conf.MongoURI == "" {
		log.Println("No database configured, state will not be saved")
		isBadDBConf = true
	}

	if conf.SMTPHost == "" {
		log.Println("SMTP host not configured, notifications will not be sent")
		isBadSMTPConf = true
	}

	if conf.SMTPPort == 0 {
		conf.SMTPPort = 25
	}

	if conf.SMTPFrom == "" {
		log.Println("Invalid mail From cofigured, notifications will not be sent")
		isBadSMTPConf = true
	}

	if conf.SMTPSubj == "" {
		conf.SMTPSubj = "Certificate Transparency monitor notification"
	}


	if conf.NotifyMatches {
		if isBadSMTPConf {
			log.Fatal("No SMTP configured, can't notificate about matches")
		}
	}

	/* override verbosity via commandline */
	if verbose {
		conf.Verbose = true
	}

	if conf.TickTime <= 0 {
		conf.TickTime = 30
	}

	var startIndex int64
	/* Init DB connection */
	if conf.MongoURI != "" {
		ctx.db, err = db.Init(conf.MongoURI)
		if err != nil || ctx.db == nil {
			isBadDBConf = true
		}

		if err == nil {
			/* Load last index state from DB */
			startIndex, err = ctx.db.LoadState()
			if err == nil {
				ctx.StartIndex = startIndex
			}
		}
	}

	/* Override index if set via config */
	if conf.StartIndex > ctx.StartIndex {
		ctx.StartIndex = conf.StartIndex
	}

	if conf.StoreMatches {
		if isBadDBConf {
			log.Print("No DB configured, can't store matches")
		}
	}

	if isBadSMTPConf && isBadDBConf {
		log.Fatal("No notifications or DB configured, no reason to start")
	}

	ctx.conf = &conf
	return nil
}

func (m *MonCtx) Serve(ctx context.Context) error {
	logClient := client.New(m.conf.LogUri)

	CNset := make(map[string]bool)
	for _, v := range m.conf.CAWhitelist {
		CNset[v] = true
	}

	matcher, err := matcher.CreateMatcherFromFlags(m.conf.MatchSubjectRegex, CNset)
	if err != nil {
		log.Fatal(err)
	}

	opts := scanner.DefaultScannerOptions()
	opts.Matcher = matcher
	opts.BatchSize = m.conf.BatchSize
	opts.NumWorkers = m.conf.NumWorkers
	opts.ParallelFetch = m.conf.ParallelFetch
	opts.StartIndex = m.StartIndex
	opts.TickTime = time.Duration(m.conf.TickTime) * time.Second
	opts.Tickers = []scanner.Ticker{scanner.LogTicker{}}
	opts.Quiet = !m.conf.Verbose
	if m.db != nil {
		opts.Tickers = append(opts.Tickers, StateSaverTicker{mon: m})
	}

	if m.db != nil && m.conf.StoreMatches {
		ch := make(chan models.MonEvent)
		m.Handlers = append(m.Handlers, ch)
		dbWorker := db.CertHandler{DB: m.db}
		go dbWorker.HandleEvents(ch)
	}

	if m.conf.NotifyMatches {
		ch := make(chan models.MonEvent)
		m.Handlers = append(m.Handlers, ch)
		smtpWorker := mail.CertHandler{Emails: m.conf.Emails, Host: m.conf.SMTPHost,
			Port: m.conf.SMTPPort, User: m.conf.SMTPUser,
			Password: m.conf.SMTPPasswd,
			From:     m.conf.SMTPFrom, Subj: m.conf.SMTPSubj}
		go smtpWorker.HandleEvents(ch)
	}

	for {
		scanner := scanner.NewScanner(logClient, *opts)
		err = scanner.Scan(func(entry *ct.LogEntry) {
			for _, ch := range m.Handlers {
				e := models.MonEvent{Type: models.CT_CERT, LogEntry: entry}
				ch <- e
			}
		}, func(entry *ct.LogEntry) {
			for _, ch := range m.Handlers {
				e := models.MonEvent{Type: models.CT_PRECERT, LogEntry: entry}
				ch <- e
			}
		})

		if m.conf.RescanPeriod <= 0 {
			break
		}
		if m.conf.Verbose {
			log.Print("Scan complete sleeping...")
		}
		/* do not fetch from old startindex in cycle */
		opts.StartIndex = m.StartIndex + int64(scanner.CertsProcessed))

		time.Sleep(time.Duration(m.conf.RescanPeriod) * time.Second)
	}

	for _, ch := range m.Handlers {
		e := models.MonEvent{Type: models.CT_QUIT, LogEntry: nil}
		ch <- e
	}

	return nil
}

type StateSaverTicker struct {
	mon *MonCtx
}

func (t StateSaverTicker) HandleTick(s *scanner.Scanner, startTime time.Time, sth *ct.SignedTreeHead) {
	if t.mon.db == nil {
		return
	}
	if t.mon.conf.Verbose {
		log.Print("Saving state to database...\n")
	}
	err := t.mon.db.SaveState(t.mon.StartIndex + int64(s.CertsProcessed))
	if err != nil {
		log.Print("Can't save state (%v)", err)
	}
}
