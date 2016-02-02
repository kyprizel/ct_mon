package cmd

import (
    "log"
    "fmt"
    "flag"
    "time"

    "golang.org/x/net/context"

    "github.com/kyprizel/ct_mon/utils"
    "github.com/kyprizel/ct_mon/pkg/mon"
)

func Run() {

    var configFile = flag.String("config", "conf/config.json", "Config file path.")
    var foreground = flag.Bool("foreground", true, "Stay in foreground.")
    var verbose = flag.Bool("verbose", false, "Print out extra logging messages, only matches.")
    flag.Parse()

    mon, err := mon.New()
    mon.SetConfig(*configFile, *verbose)

    var ctx context.Context
    var cancel context.CancelFunc

    if *foreground {
        ctx, cancel = context.WithCancel(context.TODO())
    } else {
        ctx, cancel = context.WithCancel(context.Background())
    }
    defer cancel()

    promise := utils.Promise(func() error { return mon.Serve(ctx) })

    select {
    case <-utils.NotifyInterrupt():
        log.Print("Interrupting by signal, trying to stop")
        cancel()
        select {
        case err = <-promise:
        case <-time.After(time.Second * 5):
            err = fmt.Errorf("timeout exceeded")
        }
    case err = <-promise:
    }
    if err != nil {
        log.Fatal(err)
    }
}
