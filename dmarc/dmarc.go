package dmarc

import (
	"encoding/xml"
	"fmt"
	"strings"
)

const PolicyDispositionNone = "none"

type ReportAggregator struct {
	reportsSeen map[string]bool
	Passed      map[string]int
	Failed      map[string]int
}

func NewReportAggregator() *ReportAggregator {
	var ra ReportAggregator
	ra.reportsSeen = make(map[string]bool)
	ra.Passed = make(map[string]int)
	ra.Failed = make(map[string]int)
	return &ra
}

func (ra *ReportAggregator) Count() int {
	return len(ra.reportsSeen)
}

func (ra *ReportAggregator) Add(r *Report) {
	if !ra.reportsSeen[r.ID] {
		for _, rec := range r.Records {
			if rec.PolicyDisposition != PolicyDispositionNone {
				ra.Failed[rec.Source] += rec.Count
			} else {
				ra.Passed[rec.Source] += rec.Count
			}
		}
		ra.reportsSeen[r.ID] = true
	}
}

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
	File                string
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
	fmt.Printf("Org name: %s\nEmail: %s\nID: %s\nFile name: %s\n", r.OrgName, r.Email, r.ID, r.File)
	for _, record := range r.Records {
		fmt.Printf("Source IP: %s\nCount: %d\n", record.Source, record.Count)
		fmt.Printf("Policy disposition: %s\n", record.PolicyDisposition)
		fmt.Printf("DKIM Policy: %s\nSPF Policy: %s\n", record.PolicyDKIM, record.PolicySPF)
		fmt.Printf("Reasons: %s\n", strings.Join(record.PolicyReasons, ";"))
	}
}

func (r *Report) AllPassed() bool {
	for _, r := range r.Records {
		if r.PolicyDisposition != PolicyDispositionNone {
			return false
		}
	}
	return true
}
