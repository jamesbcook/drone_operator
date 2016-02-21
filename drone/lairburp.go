package drone

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/lair-framework/go-burp"
	"github.com/lair-framework/go-lair"
)

//Burp Struct holds parsed xml data along with the settings struct
type Burp struct {
	Settings
	Parsed *burp.Issues
}

func riskToCVSS(risk string) float64 {
	switch risk {
	case "High":
		return 10.0
	case "Medium":
		return 5.0
	case "Low":
		return 3.0
	default:
		return 0.0
	}
}

//ParseBurp File
func ParseBurp(data []byte) (*burp.Issues, error) {
	b, err := burp.Parse(data)
	if err != nil {
		return nil, err
	} else if b.BurpVersion == "" {
		return nil, errors.New("Not a Burp Report")
	}
	return b, nil
}

//Build Burp Project
func (burp Burp) Build(projectID string, tags []string) (*lair.Project, error) {
	tool := "burp"
	project := &lair.Project{}
	project.ID = projectID
	project.Tool = tool
	vulnHostMap := make(map[string]hostMap)
	for _, issue := range burp.Parsed.Issues {
		if riskToCVSS(issue.Severity) == 0.0 {
			continue
		}
		lhost := &lair.Host{Tags: tags}
		u, err := url.Parse(issue.Host.Name)
		if err != nil {
			return nil, err
		}
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			//If the URL doesn't contain a port it will fail out, so we attempt to look at the scheme
			switch u.Scheme {
			case "http":
				host = u.Host
				port = "80"
			case "https":
				host = u.Host
				port = "443"
			default:
				return nil, err
			}
		}
		portNum, err := strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
		lhost.IPv4 = issue.Host.IP
		lhost.Hostnames = append(lhost.Hostnames, host)
		hostStr := fmt.Sprintf("%s:%s:%d:%s", lhost.IPv4, issue.Path, portNum, "tcp")
		//If the Issue hasn't been seen create it
		if _, ok := vulnHostMap[issue.Type]; !ok {
			v := &lair.Issue{}
			v.Title = issue.Name
			v.Description = issue.IssueBackground
			v.Solution = issue.RemediationBackground
			v.Evidence = issue.IssueDetail
			v.CVSS = riskToCVSS(issue.Severity)
			plugin := &lair.PluginID{Tool: tool, ID: issue.Type}
			v.PluginIDs = append(v.PluginIDs, *plugin)
			v.IdentifiedBy = append(v.IdentifiedBy, lair.IdentifiedBy{Tool: tool})
			vulnHostMap[issue.Type] = hostMap{Hosts: make(map[string]bool), Vulnerability: v}
		}
		v := vulnHostMap[issue.Type]
		//Create a note for each request response for a vulnerability
		note := &lair.Note{}
		note.Title = fmt.Sprintf("%s %s", issue.Host.Name+issue.Path, issue.SerialNumber)
		for _, requestResponse := range issue.RequestResponses {
			request := requestResponse.Request.Data
			response := requestResponse.Response.Data
			note.Content = fmt.Sprintf("Request:\n%s\nResponse:\n%s", request, response)
		}
		v.Vulnerability.Notes = append(v.Vulnerability.Notes, *note)
		v.Hosts[hostStr] = true
		lhost.Services = append(lhost.Services, lair.Service{Port: portNum,
			Protocol: "tcp", Service: u.Scheme})
		project.Hosts = append(project.Hosts, *lhost)
	}
	for _, hm := range vulnHostMap {
		for key := range hm.Hosts {
			tokens := strings.Split(key, ":")
			portNum, err := strconv.Atoi(tokens[2])
			if err != nil {
				return nil, err
			}
			hostKey := &lair.IssueHost{
				IPv4:     tokens[0],
				Port:     portNum,
				Protocol: tokens[3],
			}
			hm.Vulnerability.Hosts = append(hm.Vulnerability.Hosts, *hostKey)
		}
		project.Issues = append(project.Issues, *hm.Vulnerability)
	}
	c := &lair.Command{Tool: tool, Command: "Burp Scan"}
	project.Commands = append(project.Commands, *c)
	return project, nil
}
