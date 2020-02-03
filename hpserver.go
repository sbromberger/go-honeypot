package honeypot

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func logConn(conn net.Conn) net.Conn {
	log.Printf("connection from %v\n", conn.RemoteAddr())

	return conn

}

func passwordHandler(ctx ssh.Context, pass string) bool {
	u := ctx.User()
	log.Printf("User %s, password %s\n", u, pass)
	return strings.ToLower(u) == "root" && pass == "root"
}

func mkSSHHandle(hpexec string) func(ssh.Session) {
	return func(s ssh.Session) {
		mystderr := os.Stderr
		cmd := exec.Command(hpexec)

		cmdStdErr, _ := cmd.StderrPipe()

		ptyReq, winCh, isPty := s.Pty()
		if isPty {
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
			f, err := pty.Start(cmd)
			if err != nil {
				panic(err)
			}
			go func() {
				for win := range winCh {
					setWinsize(f, win.Width, win.Height)
				}
			}()
			go func() {
				io.Copy(f, s) // stdin
			}()
			go func() {
				stderr := cmdStdErr
				fmt.Println("in stderr")
				io.Copy(mystderr, stderr)

			}()
			io.Copy(s, f) // stdout
			cmd.Wait()
		} else {
			io.WriteString(s, "No PTY requested.\n")
			s.Exit(1)
		}
	}

}
func NewHpServer(port int, keyfile string, hpexec string) *ssh.Server {
	s := &ssh.Server{
		Addr:            fmt.Sprintf(":%d", port),
		Handler:         mkSSHHandle(hpexec),
		ConnCallback:    logConn,
		PtyCallback:     func(c ssh.Context, _ ssh.Pty) bool { return true },
		PasswordHandler: passwordHandler,
	}
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
	}

	// Create the Signer for this private key.
	signer, err := gossh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}
	s.AddHostKey(signer)
	return s
}
