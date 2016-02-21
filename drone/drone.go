package drone

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"

	"github.com/lair-framework/api-server/client"
	"github.com/lair-framework/go-lair"
)

//Settings For Drones
type Settings struct {
	ProjectID string
	Tags      []string
}

type hostMap struct {
	Hosts         map[string]bool
	Vulnerability *lair.Issue
}

//Project Building
type Project interface {
	Build(projectID string, tags []string) (*lair.Project, error)
}

//Import Project Data into Liar
func Import(project *lair.Project) error {
	forcePorts := false
	insecureSSL := true
	limitHosts := false
	lairURL := os.Getenv("LAIR_API_SERVER")
	if lairURL == "" {
		return errors.New("Fatal: Missing LAIR_API_SERVER environment variable")
	}
	u, err := url.Parse(lairURL)
	if err != nil {
		return fmt.Errorf("Fatal: Error parsing LAIR_API_SERVER URL. Error %s", err.Error())
	}
	if u.User == nil {
		return errors.New("Fatal: Missing username and/or password")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		return errors.New("Fatal: Missing username and/or password")
	}
	c, err := client.New(&client.COptions{
		User:               user,
		Password:           pass,
		Host:               u.Host,
		Scheme:             u.Scheme,
		InsecureSkipVerify: insecureSSL,
	})
	if err != nil {
		return fmt.Errorf("Fatal: Error setting up client. Error %s", err.Error())
	}
	res, err := c.ImportProject(&client.DOptions{ForcePorts: forcePorts, LimitHosts: limitHosts}, project)
	if err != nil {
		return fmt.Errorf("Fatal: Unable to import project. Error %s", err.Error())
	}
	defer res.Body.Close()
	droneRes := &client.Response{}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("Fatal: Error %s", err.Error())
	}
	if err := json.Unmarshal(body, droneRes); err != nil {
		return fmt.Errorf("Fatal: Could not unmarshal JSON. Error %s", err.Error())
	}
	if droneRes.Status == "Error" {
		return fmt.Errorf("Fatal: Import failed. Error %s", droneRes.Message)
	}
	return nil
}
