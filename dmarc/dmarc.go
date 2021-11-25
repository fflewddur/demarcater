package dmarc

import (
	"encoding/xml"
	"fmt"
	"strings"
)

type Report struct {
	OrgName             string    `xml:"report_metadata>org_name"`
	Email               string    `xml:"report_metadata>email"`
	ContactInfo         string    `xml:"report_metadata>extra_contact_info"`
	ID                  string    `xml:"report_metadata>report_id"`
	StartTimestamp      int       `xml:"report_metadata>date_range>begin"`
	EndTimestamp        int       `xml:"report_metadata>date_range>end"`
	Errors              []string  `xml:"report_metadata>error"`
	PolicyDomain        string    `xml:"policy_published>domain"`
	PolicyDKIMAlignment string    `xml:"policy_published>adkim"`
	PolicySPFAlignment  string    `xml:"policy_published>aspf"`
	DomainPolicy        string    `xml:"policy_published>p"`
	SubdomainPolicy     string    `xml:"policy_published>sp"`
	PolicyPercent       int       `xml:"policy_published>pct"`
	FailureReporting    string    `xml:"policy_published>fo"`
	Records             []*Record `xml:"record"`
}

type Record struct {
	Source            string        `xml:"row>source_ip"`
	Count             int           `xml:"row>count"`
	PolicyDisposition string        `xml:"row>policy_evaluated>disposition"`
	PolicyDKIM        string        `xml:"row>policy_evaluated>dkim"`
	PolicySPF         string        `xml:"row>policy_evaluated>spf"`
	PolicyReasons     []string      `xml:"row>policy_evaluated>reason"`
	HeaderFrom        string        `xml:"identifiers>header_from"`
	EnvelopeTo        string        `xml:"identifiers>envelope_to"`
	EnvelopeFrom      string        `xml:"identifiers>envelope_from"`
	ResultsDKIM       []*AuthResult `xml:"auth_results>dkim"`
	ResultsSPF        []*AuthResult `xml:"auth_results>spf"`
}

type AuthResult struct {
	Domain      string `xml:"domain"`
	Result      string `xml:"result"`
	Selector    string `xml:"selector"`
	HumanResult string `xml:"human_result"`
}

func ReadReport(data []byte) (report *Report, err error) {
	var r Report
	err = xml.Unmarshal(data, &r)
	if err != nil {
		return
	}
	report = &r
	return
}

func (r *Report) PrettyPrint() {
	fmt.Printf("Org name: %s\nEmail: %s\nID: %s\n", r.OrgName, r.Email, r.ID)
	for _, record := range r.Records {
		fmt.Printf("Source IP: %s\nCount: %d\n", record.Source, record.Count)
		fmt.Printf("DKIM Policy: %s\nSPF Policy: %s\n", record.PolicyDKIM, record.PolicySPF)
		fmt.Printf("Reasons: %s\n", strings.Join(record.PolicyReasons, ";"))
	}
}

func (r *Report) AllPassed() bool {
	for _, r := range r.Records {
		if r.PolicyDKIM != "pass" || r.PolicySPF != "pass" {
			return false
		}
	}
	return true
}
