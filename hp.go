package honeypot

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

type Honeypot struct {
	Welcome    func()
	Ps1        func()
	UnknownCmd HoneyCmd
	Cmds       HoneyCmds
}

func (hp *Honeypot) Help(cmd []string) {
	var b strings.Builder
	if len(cmd) == 1 { // no arguments
		for _, hc := range hp.Cmds {
			fmt.Fprintf(&b, "%s\n", hc.Helpstr)
		}
	} else {
		for _, c := range cmd {
			if hc, found := hp.Cmds[c]; found {
				fmt.Fprintf(&b, "%s\n", hc.Helpstr)
			}
		}
	}
	fmt.Fprintf(&b, "help {cmd}: help on optional cmd\n")
	fmt.Fprintf(&b, "exit: terminate session\n")
	fmt.Println(b.String())

}

type HoneyCmd struct {
	Helpstr string
	Cmd     func([]string)
}

type HoneyCmds map[string]HoneyCmd

func (h *HoneyCmds) AddCmd(s string, help string, c HoneyCmd) {
	(*h)[s] = c
}

// Exec executes a honeypot for a given connection.
func (hp *Honeypot) Exec() {
	scanner := bufio.NewScanner(os.Stdin)
	hp.Welcome()
	hp.Ps1()
	for scanner.Scan() {
		ins := scanner.Text()
		log.Println("in: ", ins, "nbytes:", len(ins))
		if len(ins) > 0 {
			insSplit := strings.Split(ins, " ")
			cmd := insSplit[0]
			switch cmd {
			case "help":
				hp.Help(insSplit)
			case "exit":
				fmt.Println("Goodbye.")
				return
			default:
				hfn, found := hp.Cmds[cmd]
				if !found {
					hfn = hp.UnknownCmd
				}
				hfn.Cmd(insSplit)
			}
		}
		hp.Ps1()
	}
}
