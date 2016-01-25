package drone

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/lair-framework/go-lair"
	"github.com/lair-framework/go-nessus"
)

//Nessus Struct holds parsed xml data along with the settings struct
type Nessus struct {
	Settings Settings
	Parsed   *nessus.NessusData
}

type hostMap struct {
	Hosts         map[string]bool
	Vulnerability *lair.Issue
}

//ParseNessus File
func ParseNessus(data []byte) (n *nessus.NessusData, err error) {
	n, err = nessus.Parse(data)
	if err != nil {
		return nil, err
	} else if n.Report.Name == "" {
		return nil, errors.New("Not a Nessus Report")
	}
	return n, err
}

//Build Nessus Project
func (nessus Nessus) Build(projectID string, tags []string) (*lair.Project, error) {
	tool := "nessus"
	osWeight := 75
	cvePattern := regexp.MustCompile(`(CVE-|CAN-)`)
	falseUDPPattern := regexp.MustCompile(`.*\?$`)
	noteID := 1

	project := &lair.Project{}
	project.Tool = tool
	project.ID = projectID

	vulnHostMap := make(map[string]hostMap)
	for _, reportHost := range nessus.Parsed.Report.ReportHosts {
		tempIP := reportHost.Name
		host := &lair.Host{
			Tags: tags,
		}
		for _, tag := range reportHost.HostProperties.Tags {
			switch {
			case tag.Name == "operating-system":
				os := &lair.OS{
					Tool:        tool,
					Weight:      osWeight,
					Fingerprint: tag.Data,
				}
				host.OS = *os
			case tag.Name == "host-ip":
				host.IPv4 = tag.Data
			case tag.Name == "mac-address":
				host.MAC = tag.Data
			case tag.Name == "host-fqdn":
				host.Hostnames = append(host.Hostnames, tag.Data)
			case tag.Name == "netbios-name":
				host.Hostnames = append(host.Hostnames, tag.Data)
			}
		}

		portsProcessed := make(map[string]lair.Service)
		for _, item := range reportHost.ReportItems {
			pluginID := item.PluginID
			pluginFamily := item.PluginFamily
			severity := item.Severity
			title := item.PluginName
			port := item.Port
			protocol := item.Protocol
			service := item.SvcName
			evidence := item.PluginOutput

			// Check for false positive UDP...ignore it if found.
			if protocol == "udp" && falseUDPPattern.MatchString(service) {
				continue
			}

			portKey := fmt.Sprintf("%d:%s", port, protocol)
			if _, ok := portsProcessed[portKey]; !ok {
				// Haven't seen this port. Create it.
				p := &lair.Service{
					Port:     port,
					Protocol: protocol,
					Service:  service,
				}
				portsProcessed[portKey] = *p
			}

			if evidence != "" && severity >= 1 && pluginFamily != "Port scanners" && pluginFamily != "Service detection" {
				// Format and add evidence
				note := &lair.Note{
					Title:          fmt.Sprintf("%s (ID%d)", title, noteID),
					Content:        "",
					LastModifiedBy: tool,
				}
				e := strings.Trim(evidence, " \t")
				for _, line := range strings.Split(e, "\n") {
					line = strings.Trim(line, " \t")
					if line != "" {
						note.Content += "    " + line + "\n"
					}
				}
				p := portsProcessed[portKey]
				p.Notes = append(p.Notes, *note)
				portsProcessed[portKey] = p
				noteID++
			}

			if pluginID == "19506" {
				command := &lair.Command{
					Tool:    tool,
					Command: item.PluginOutput,
				}
				if project.Commands == nil || len(project.Commands) == 0 {
					project.Commands = append(project.Commands, *command)
				}
				continue
			}

			if _, ok := vulnHostMap[pluginID]; !ok {
				// Vulnerability has not yet been seen for this host. Add it.
				v := &lair.Issue{}

				v.Title = title
				v.Description = item.Description
				v.Solution = item.Solution
				v.Evidence = evidence
				v.IsFlagged = item.ExploitAvailable
				if item.ExploitAvailable {
					exploitDetail := item.ExploitFrameworkMetasploit
					if exploitDetail {
						note := &lair.Note{
							Title:          "Metasploit Exploit",
							Content:        "Exploit exists. Details unknown.",
							LastModifiedBy: tool,
						}
						if item.MetasploitName != "" {
							note.Content = item.MetasploitName
						}
						v.Notes = append(v.Notes, *note)
					}

					exploitDetail = item.ExploitFrameworkCanvas
					if exploitDetail {
						note := &lair.Note{
							Title:          "Canvas Exploit",
							Content:        "Exploit exists. Details unknown.",
							LastModifiedBy: tool,
						}
						if item.CanvasPackage != "" {
							note.Content = item.CanvasPackage
						}
						v.Notes = append(v.Notes, *note)
					}

					exploitDetail = item.ExploitFrameworkCore
					if exploitDetail {
						note := &lair.Note{
							Title:          "Core Impact Exploit",
							Content:        "Exploit exists. Details unknown.",
							LastModifiedBy: tool,
						}
						if item.CoreName != "" {
							note.Content = item.CoreName
						}
						v.Notes = append(v.Notes, *note)
					}
				}

				v.CVSS = item.CVSSBaseScore
				if v.CVSS == 0 && item.RiskFactor != "" && item.RiskFactor != "Low" {
					switch {
					case item.RiskFactor == "Medium":
						v.CVSS = 5.0
					case item.RiskFactor == "High":
						v.CVSS = 7.5
					case item.RiskFactor == "Critical":
						v.CVSS = 10
					}
				}

				if v.CVSS == 0 {
					// Ignore informational findings
					continue
				}

				// Set the CVEs
				for _, cve := range item.CVE {
					c := cvePattern.ReplaceAllString(cve, "")
					v.CVEs = append(v.CVEs, c)
				}

				// Set the plugin and identified by information
				plugin := &lair.PluginID{Tool: tool, ID: pluginID}
				v.PluginIDs = append(v.PluginIDs, *plugin)
				v.IdentifiedBy = append(v.IdentifiedBy, lair.IdentifiedBy{Tool: tool})

				vulnHostMap[pluginID] = hostMap{Hosts: make(map[string]bool), Vulnerability: v}

			}

			if hm, ok := vulnHostMap[pluginID]; ok {
				hostStr := fmt.Sprintf("%s:%d:%s", host.IPv4, port, protocol)
				hm.Hosts[hostStr] = true
			}
		}

		if host.IPv4 == "" {
			host.IPv4 = tempIP
		}

		// Add ports to host and host to project
		for _, p := range portsProcessed {
			host.Services = append(host.Services, p)
		}
		project.Hosts = append(project.Hosts, *host)
	}

	for _, hm := range vulnHostMap {
		for key := range hm.Hosts {
			tokens := strings.Split(key, ":")
			portNum, err := strconv.Atoi(tokens[1])
			if err != nil {
				return nil, err
			}
			hostKey := &lair.IssueHost{
				IPv4:     tokens[0],
				Port:     portNum,
				Protocol: tokens[2],
			}
			hm.Vulnerability.Hosts = append(hm.Vulnerability.Hosts, *hostKey)
		}
		project.Issues = append(project.Issues, *hm.Vulnerability)
	}

	if len(project.Commands) == 0 {
		c := &lair.Command{Tool: tool, Command: "Nessus scan - command unknown"}
		project.Commands = append(project.Commands, *c)
	}

	return project, nil
}
