package main

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/sbromberger/honeypot"
)

func welcome() {
	fmt.Println("Goswood Park AMI MDMS Server, v1.10.56b. Authorized access only.\nLogged in as root.")
	fmt.Println()
}

func ps1() {
	fmt.Print("# ")
}

// returns a deterministic float64 from the premise id.
func fracFromPremID(p string) float64 {
	var c int64
	for i, b := range []byte(p) {
		c = c<<i + 6 + int64(b)
	}
	rand.Seed(c)
	return rand.Float64()
}

func meterUsage(p string) (float64, time.Time, float64, bool) {
	f := fracFromPremID(p)
	t := time.Now()

	// ft := f
	// if f < 0.2 {
	// 	ft = 0.2 + f
	// }
    //
	// if f > 0.9 {
	// 	ft = f - 0.1
	// }
	f20m := int(1200 * f)
	t = t.Add(-1 * time.Hour).Round(20 * time.Minute).Add(time.Duration(f20m) * time.Second)
	u := t.Unix() - 29145600
	rate := 0.000001 * f
	usage := float64(u) * rate
	balance := 100 * f
	current := f < 0.8 && balance < 80
	return usage, t.UTC(), balance, current
}

func unknownCmd(cmd []string) {
	fmt.Printf("%s: unknown command ('help' for help)\n", cmd[0])
}

func shortSleep() {
	d := rand.Intn(1000) + 800
	time.Sleep(time.Duration(d) * time.Millisecond)
}

func longSleep() {
	d := rand.Intn(1200) + 2000
	time.Sleep(time.Duration(d) * time.Millisecond)
}

func validatePremID(p string) bool {
	_, err := strconv.Atoi(p)
	return err == nil && len(p) == 10
}

func premIDExists(p string) bool {
	return strings.HasPrefix(p, "0")
}

func meterStat(cmd []string) {
	if len(cmd) < 2 {
		fmt.Println("premise ID required")
		return
	}

	premID := cmd[1]
	if !validatePremID(premID) {
		fmt.Println("invalid premise ID (format: dddddddddd)")
		return
	}
	fmt.Println("submitting status request for Premise ID", premID)
	shortSleep()
	fmt.Println("successfully submitted status request for Premise ID", premID)
	longSleep()
	if premIDExists(premID) {
		s, t, b, c := meterUsage(premID)
		fmt.Println("Meter Status for Premise ID", premID, "as of", time.Now().UTC().Format(time.UnixDate))
		fmt.Println("Current usage: ", s)
		fmt.Printf("Balance due: $%0.2f\n", b)
		fmt.Println("Account current: ", c)
		fmt.Println("Last query: ", t.Format(time.UnixDate))
	} else {
		fmt.Println("Premise ID", premID, "not found in environment")
	}
}

func powerOn(cmd []string) {
	if len(cmd) < 2 {
		fmt.Println("premise ID required")
		return
	}

	premID := cmd[1]
	if !validatePremID(premID) {
		fmt.Println("invalid premise ID (format: dddddddddd)")
		return
	}

	fmt.Println("submitting reconnect request for Premise ID", premID)
	shortSleep()
	fmt.Println("successfully submitted reconnect request for Premise ID", premID)
	longSleep()
	if premIDExists(premID) {
		fmt.Println("disconnect processed and confirmed for Premise ID", premID)
	} else {
		fmt.Println("Premise ID", premID, "not found in environment")
	}
}

func powerOff(cmd []string) {
	if len(cmd) < 2 {
		fmt.Println("premise ID required")
		return
	}

	premID := cmd[1]
	if !validatePremID(premID) {
		fmt.Println("invalid premise ID (format: dddddddddd)")
		return
	}

	fmt.Println("submitting disconnect request for Premise ID", premID)
	shortSleep()
	fmt.Println("successfully submitted disconnect request for Premise ID", premID)
	longSleep()
	if premIDExists(premID) {
		fmt.Println("disconnect processed and confirmed for Premise ID", premID)
	} else {
		fmt.Println("Premise ID", premID, "not found in environment")
	}
}

func main() {
	cmds := make(honeypot.HoneyCmds)
	cmds["poweron"] = honeypot.HoneyCmd{"poweron <premid>: issue remote reconnect command for premise ID <premid>", powerOn}
	cmds["poweroff"] = honeypot.HoneyCmd{"poweroff <premid>: issue remote disconnect command for premise ID <premid>", powerOff}
	cmds["stat"] = honeypot.HoneyCmd{"stat <premid>: issue status request for premise ID <premid>", meterStat}

	unk := honeypot.HoneyCmd{"unknown", unknownCmd}
	hp := honeypot.Honeypot{welcome, ps1, unk, cmds}
	hp.Exec()

}
