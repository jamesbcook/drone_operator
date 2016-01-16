package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
)

const (
	binDir string = "./bin/"
	help   string = ` Options:
	drone_operator -setup
	drone_operator -run -host <ip> -port <port>
	`
)

var runningOS string

type flagOpts struct {
	setup bool
	run   bool
	host  string
	port  int
	help  bool
}

func binDirExists() bool {
	_, err := os.Stat(binDir)
	if err == nil {
		return true
	}
	return false
}

func binDirMake() {
	err := os.Mkdir(binDir, 0775)
	if err != nil {
		log.Fatal("Can't make dir", err)
	}
}

func createURL(binary, version string) string {
	var file string
	switch runningOS {
	case "windows":
		file = fmt.Sprintf("drone-%s_windows_amd64.exe", binary)
	case "linux":
		file = fmt.Sprintf("drone-%s_linux_amd64", binary)
	case "darwin":
		file = fmt.Sprintf("drone-%s_darwin_amd64", binary)
	}
	url := fmt.Sprintf("https://github.com/lair-framework/drone-%s/releases/download/v%s/%s", binary, version, file)
	return url
}

func setup() {
	res := binDirExists()
	if res == false {
		binDirMake()
	}
	binaries := map[string]string{
		"blacksheepwall": "2.0.0",
		"nmap":           "2.1.0",
		"nessus":         "2.1.0",
	}
	for binary, version := range binaries {
		fmt.Println("Downloading", binary)
		url := createURL(binary, version)
		downloadLocation := fmt.Sprintf("%s/%s", binDir, binary)
		out, err := os.Create(downloadLocation)
		if err != nil {
			fmt.Println("Error creating", binary)
		}
		defer out.Close()
		resp, err := http.Get(url)
		if err != nil {
			fmt.Println("Error Getting Package", binary, err)
		}
		defer resp.Body.Close()
		_, err = io.Copy(out, resp.Body)
		err = os.Chmod(downloadLocation, 0775)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func flags() *flagOpts {
	setupOpt := flag.Bool("setup", false, "Run Setup")
	runOpt := flag.Bool("run", false, "Start Server")
	hostOpt := flag.String("host", "localhost", "Host for Server")
	portOpt := flag.Int("port", 8080, "Port for Server")
	helpOpt := flag.Bool("help", false, "Print Help")
	flag.Parse()
	return &flagOpts{setup: *setupOpt, run: *runOpt,
		host: *hostOpt, port: *portOpt, help: *helpOpt}
}

func init() {
	runningOS = runtime.GOOS
}

func main() {
	options := flags()
	if options.setup {
		setup()
	} else if options.run {

	} else if options.help {
		fmt.Println(help)
	} else {
		fmt.Println("No Options Set")
		fmt.Println(help)
		os.Exit(1)
	}
}
