package drone

import (
	"errors"

	"github.com/lair-framework/go-lair"
	"github.com/lair-framework/go-nmap"
)

//Nmap Struct holds parsed xml data along with the settings struct
type Nmap struct {
	Settings Settings
	Parsed   *nmap.NmapRun
}

//ParseNmap File
func ParseNmap(data []byte) (n *nmap.NmapRun, err error) {
	n, err = nmap.Parse(data)
	if err != nil {
		return nil, err
	} else if n.Version == "" {
		return nil, errors.New("Not an Nmap File")
	}
	return n, err
}

//Build Nmap Project
func (nmap Nmap) Build(projectID string, tags []string) (*lair.Project, error) {
	tool := "nmap"
	osWeight := 50
	project := &lair.Project{}
	project.ID = projectID
	project.Tool = tool
	project.Commands = append(project.Commands, lair.Command{Tool: tool, Command: nmap.Parsed.Args})

	for _, h := range nmap.Parsed.Hosts {
		host := &lair.Host{Tags: tags}
		if h.Status.State != "up" {
			continue
		}

		for _, address := range h.Addresses {
			switch {
			case address.AddrType == "ipv4":
				host.IPv4 = address.Addr
			case address.AddrType == "mac":
				host.MAC = address.Addr
			}
		}

		for _, hostname := range h.Hostnames {
			host.Hostnames = append(host.Hostnames, hostname.Name)
		}

		for _, p := range h.Ports {
			service := lair.Service{}
			service.Port = p.PortId
			service.Protocol = p.Protocol

			if p.State.State != "open" {
				continue
			}

			if p.Service.Name != "" {
				service.Service = p.Service.Name
				service.Product = "Unknown"
				if p.Service.Product != "" {
					service.Product = p.Service.Product
					if p.Service.Version != "" {
						service.Product += " " + p.Service.Version
					}
				}
			}

			for _, script := range p.Scripts {
				note := &lair.Note{Title: script.Id, Content: script.Output, LastModifiedBy: tool}
				service.Notes = append(service.Notes, *note)
			}

			host.Services = append(host.Services, service)
		}

		if len(h.Os.OsMatch) > 0 {
			os := lair.OS{}
			os.Tool = tool
			os.Weight = osWeight
			os.Fingerprint = h.Os.OsMatch[0].Name
			host.OS = os
		}

		project.Hosts = append(project.Hosts, *host)

	}

	return project, nil
}
