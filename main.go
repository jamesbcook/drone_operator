package main

import (
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/b00stfr3ak/drone_operator/drone"
	"github.com/gorilla/sessions"
)

const (
	help string = `Usage:
	drone_operator -host <ip> -port <port>
	`
)

var (
	store = sessions.NewCookieStore([]byte("98F#FG2u27Yypb#^9qBfEZ!sK^6O5v#1"))
)

type flagOpts struct {
	host string
	port int
	help bool
}

//Page struct includes data to fill out HTML pages
type Page struct {
	Title   string
	Alert   map[string][]interface{}
	Message bool
}

func processFile(settings *drone.Settings, data []byte) error {
	var project drone.Project
	n, err := drone.ParseNmap(data)
	if err == nil {
		nmap := &drone.Nmap{Settings: *settings, Parsed: n}
		project = nmap
	} else if err != nil {
		n, err := drone.ParseNessus(data)
		if err == nil {
			nessus := &drone.Nessus{Settings: *settings, Parsed: n}
			project = nessus
		} else if err != nil {
			b, err := drone.ParseBurp(data)
			if err == nil {
				burp := &drone.Burp{Settings: *settins, Parsed: b}
				project = burp
			} else if err != nil {
				log.Println(err)
			}
		}
	}
	p, err := project.Build(settings.ProjectID, settings.Tags)
	if err != nil {
		log.Println(err)
	}
	return drone.Import(p)
}

func upload(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "flash-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	err = r.ParseMultipartForm(10 << 20)
	if err != nil {
		log.Println("ParseMultipartForm error:", err)
		return
	}
	pid := r.FormValue("pid")
	tags := r.FormValue("tags")
	hostTags := []string{}
	if tags != "" {
		hostTags = strings.Split(tags, ",")
	}
	settings := &drone.Settings{ProjectID: pid, Tags: hostTags}
	for _, fheaders := range r.MultipartForm.File {
		for _, header := range fheaders {
			f, err := header.Open()
			if err != nil {
				log.Println("file open error", err)
				continue
			}
			var buff bytes.Buffer
			buff.ReadFrom(f)
			f.Close()
			err = processFile(settings, buff.Bytes())
			if err != nil {
				errmsg := fmt.Sprintf("%s: %s", err, header.Filename)
				log.Println(errmsg)
				session.AddFlash(errmsg, "alert alert-danger")
			} else {
				goodmsg := fmt.Sprintf("Upload Successful %s", header.Filename)
				log.Println(goodmsg)
				session.AddFlash(goodmsg, "alert alert-success")
			}
		}
	}
	session.Save(r, w)
	http.Redirect(w, r, "/", 302)
}

func index(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "flash-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	p := &Page{Title: "Upload Page"}
	bm := session.Flashes("alert alert-danger")
	gm := session.Flashes("alert alert-success")
	p.Alert = make(map[string][]interface{})
	if len(bm) > 0 {
		p.Message = true
		p.Alert["alert alert-danger"] = bm
	}
	if len(gm) > 0 {
		p.Message = true
		p.Alert["alert alert-success"] = gm
	}
	t, _ := template.ParseFiles("app/views/index/index.html")
	session.Save(r, w)
	t.Execute(w, p)
}

func run(host string, port int) {
	server := fmt.Sprintf("%s:%d", host, port)
	fs := http.FileServer(http.Dir("public/"))
	http.Handle("/public/", http.StripPrefix("/public/", fs))
	http.HandleFunc("/", index)
	http.HandleFunc("/upload", upload)
	log.Println("Starting Server at", server)
	err := http.ListenAndServe(server, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func flags() *flagOpts {
	hostOpt := flag.String("host", "localhost", "Host for Server")
	portOpt := flag.Int("port", 8080, "Port for Server")
	flag.Usage = func() {
		fmt.Println(help)
	}
	flag.Parse()
	return &flagOpts{host: *hostOpt, port: *portOpt}
}

func main() {
	options := flags()
	if options.help {
		fmt.Println(help)
	} else {
		run(options.host, options.port)
	}
}
