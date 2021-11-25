package dmarc

import "testing"

func TestReadReport(t *testing.T) {
	data := `
	<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <extra_contact_info>https://support.google.com/a/answer/2466580</extra_contact_info>
    <report_id>18370231347925571349</report_id>
    <date_range>
      <begin>1637452800</begin>
      <end>1637539199</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>dropline.net</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>209.85.220.69</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>dropline.net</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>dropline.net</domain>
        <result>pass</result>
        <selector>google</selector>
      </dkim>
      <spf>
        <domain>dropline.net</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>209.85.220.41</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>dropline.net</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>dropline.net</domain>
        <result>pass</result>
        <selector>google</selector>
      </dkim>
      <spf>
        <domain>dropline.net</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>
`
	report, err := ReadReport([]byte(data))
	if err != nil {
		t.Fatalf(`ReadReport() returned an error: %v`, err)
	}
	want := Report{
		OrgName:             "google.com",
		Email:               "noreply-dmarc-support@google.com",
		ContactInfo:         "https://support.google.com/a/answer/2466580",
		ID:                  "18370231347925571349",
		StartTimestamp:      1637452800,
		EndTimestamp:        1637539199,
		PolicyDomain:        "dropline.net",
		PolicyDKIMAlignment: "r",
		PolicySPFAlignment:  "r",
		DomainPolicy:        "reject",
		SubdomainPolicy:     "reject",
		PolicyPercent:       100,
		Records: []*Record{
			{
				Source:            "209.85.220.69",
				Count:             1,
				PolicyDisposition: "none",
				PolicyDKIM:        "pass",
				PolicySPF:         "pass",
				HeaderFrom:        "dropline.net",
				ResultsDKIM: []*AuthResult{
					{
						Result:   "pass",
						Domain:   "dropline.net",
						Selector: "google",
					},
				},
				ResultsSPF: []*AuthResult{
					{
						Result: "pass",
						Domain: "dropline.net",
					},
				},
			},
			{
				Source:            "209.85.220.41",
				Count:             1,
				PolicyDisposition: "none",
				PolicyDKIM:        "pass",
				PolicySPF:         "pass",
				HeaderFrom:        "dropline.net",
				ResultsDKIM: []*AuthResult{
					{
						Result:   "pass",
						Domain:   "dropline.net",
						Selector: "google",
					},
				},
				ResultsSPF: []*AuthResult{
					{
						Result: "pass",
						Domain: "dropline.net",
					},
				},
			},
		},
	}

	// Report metadata
	if report.OrgName != want.OrgName {
		t.Fatalf(`report.OrgName = %q, want %q`, report.OrgName, want.OrgName)
	}
	if report.Email != want.Email {
		t.Fatalf(`report.Email = %q, want %q`, report.Email, want.Email)
	}
	if report.ContactInfo != want.ContactInfo {
		t.Fatalf(`report.ContactInfo = %q, want %q`, report.ContactInfo, want.ContactInfo)
	}
	if report.ID != want.ID {
		t.Fatalf(`report.ID = %q, want %q`, report.ID, want.ID)
	}
	if report.StartTimestamp != want.StartTimestamp {
		t.Fatalf(`report.StartTimestamp = %q, want %q`, report.StartTimestamp, want.StartTimestamp)
	}
	if report.EndTimestamp != want.EndTimestamp {
		t.Fatalf(`report.ID = %q, want %q`, report.EndTimestamp, want.EndTimestamp)
	}
	if len(report.Errors) != 0 {
		t.Fatalf(`report.Errors = %q, want %q`, report.Errors, want.Errors)
	}

	// Policy
	if report.PolicyDomain != want.PolicyDomain {
		t.Fatalf(`report.PolicyDomain = %q, want %q`, report.PolicyDomain, want.PolicyDomain)
	}
	if report.PolicyDKIMAlignment != want.PolicyDKIMAlignment {
		t.Fatalf(`report.PolicyDKIMAlignment = %q, want %q`, report.PolicyDKIMAlignment, want.PolicyDKIMAlignment)
	}
	if report.PolicySPFAlignment != want.PolicySPFAlignment {
		t.Fatalf(`report.PolicySPFAlignment = %q, want %q`, report.PolicySPFAlignment, want.PolicySPFAlignment)
	}
	if report.DomainPolicy != want.DomainPolicy {
		t.Fatalf(`report.DomainPolicy = %q, want %q`, report.DomainPolicy, want.DomainPolicy)
	}
	if report.SubdomainPolicy != want.SubdomainPolicy {
		t.Fatalf(`report.SubdomainPolicy = %q, want %q`, report.SubdomainPolicy, want.SubdomainPolicy)
	}
	if report.PolicyPercent != want.PolicyPercent {
		t.Fatalf(`report.PolicyPercent = %q, want %q`, report.PolicyPercent, want.PolicyPercent)
	}
	if report.FailureReporting != want.FailureReporting {
		t.Fatalf(`report.SubdomainPolicy = %q, want %q`, report.FailureReporting, want.FailureReporting)
	}

	// Records
	if len(report.Records) != len(want.Records) {
		t.Fatalf(`len(report.Records) = %q, want %q`, len(report.Records), 2)
	}
	for i := 0; i < 2; i++ {
		if report.Records[i].Source != want.Records[i].Source {
			t.Fatalf(`report.Records[%d].Source = %q, want %q`, i, report.Records[i].Source, want.Records[i].Source)
		}
		if report.Records[i].Count != want.Records[i].Count {
			t.Fatalf(`report.Records[%d].Count = %q, want %q`, i, report.Records[i].Count, want.Records[i].Count)
		}
		if report.Records[i].PolicyDisposition != want.Records[i].PolicyDisposition {
			t.Fatalf(`report.Records[%d].PolicyDisposition = %q, want %q`, i, report.Records[i].PolicyDisposition, want.Records[i].PolicyDisposition)
		}
		if report.Records[i].PolicyDKIM != want.Records[i].PolicyDKIM {
			t.Fatalf(`report.Records[%d].PolicyDKIM = %q, want %q`, i, report.Records[i].PolicyDKIM, want.Records[i].PolicyDKIM)
		}
		if report.Records[i].PolicySPF != want.Records[i].PolicySPF {
			t.Fatalf(`report.Records[%d].PolicySPF = %q, want %q`, i, report.Records[i].PolicySPF, want.Records[i].PolicySPF)
		}
		if report.Records[i].HeaderFrom != want.Records[i].HeaderFrom {
			t.Fatalf(`report.Records[%d].HeaderFrom = %q, want %q`, i, report.Records[i].HeaderFrom, want.Records[i].HeaderFrom)
		}
		if report.Records[i].EnvelopeFrom != want.Records[i].EnvelopeFrom {
			t.Fatalf(`report.Records[%d].EnvelopeFrom = %q, want %q`, i, report.Records[i].EnvelopeFrom, want.Records[i].EnvelopeFrom)
		}
		if report.Records[i].EnvelopeTo != want.Records[i].EnvelopeTo {
			t.Fatalf(`report.Records[%d].EnvelopeTo = %q, want %q`, i, report.Records[i].EnvelopeTo, want.Records[i].EnvelopeTo)
		}
		if len(report.Records[i].ResultsDKIM) != len(want.Records[i].ResultsDKIM) {
			t.Fatalf(`len(report.Records[%d].ResultsDKIM) = %q, want %q`, i, len(report.Records[i].ResultsDKIM), len(want.Records[i].ResultsDKIM))
		}
		if len(report.Records[i].ResultsSPF) != len(want.Records[i].ResultsSPF) {
			t.Fatalf(`len(report.Records[%d].ResultsSPF) = %q, want %q`, i, len(report.Records[i].ResultsSPF), len(want.Records[i].ResultsSPF))
		}
		if report.Records[i].ResultsDKIM[0].Domain != want.Records[i].ResultsDKIM[0].Domain {
			t.Fatalf(`report.Records[%d].ResultsDKIM[0].Domain = %q, want %q`,
				i, report.Records[i].ResultsDKIM[0].Domain, want.Records[i].ResultsDKIM[0].Domain)
		}
		if report.Records[i].ResultsDKIM[0].Result != want.Records[i].ResultsDKIM[0].Result {
			t.Fatalf(`report.Records[%d].ResultsDKIM[0].Result = %q, want %q`,
				i, report.Records[i].ResultsDKIM[0].Result, want.Records[i].ResultsDKIM[0].Result)
		}
		if report.Records[i].ResultsDKIM[0].Selector != want.Records[i].ResultsDKIM[0].Selector {
			t.Fatalf(`report.Records[%d].ResultsDKIM[0].Selector = %q, want %q`,
				i, report.Records[i].ResultsDKIM[0].Selector, want.Records[i].ResultsDKIM[0].Selector)
		}
		if report.Records[i].ResultsDKIM[0].HumanResult != want.Records[i].ResultsDKIM[0].HumanResult {
			t.Fatalf(`report.Records[%d].ResultsDKIM[0].HumanResult = %q, want %q`, i,
				report.Records[i].ResultsDKIM[0].HumanResult, want.Records[i].ResultsDKIM[0].HumanResult)
		}
		if report.Records[i].ResultsSPF[0].Domain != want.Records[i].ResultsSPF[0].Domain {
			t.Fatalf(`report.Records[%d].ResultsSPF[0].Domain = %q, want %q`,
				i, report.Records[i].ResultsSPF[0].Domain, want.Records[i].ResultsSPF[0].Domain)
		}
		if report.Records[i].ResultsSPF[0].Result != want.Records[i].ResultsSPF[0].Result {
			t.Fatalf(`report.Records[%d].ResultsSPF[0].Result = %q, want %q`,
				i, report.Records[i].ResultsSPF[0].Result, want.Records[i].ResultsSPF[0].Result)
		}
	}

}
