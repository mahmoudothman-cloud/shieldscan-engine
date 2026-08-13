package nmap

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// XML schema structs mirror Nmap's nmap-dtd published schema.
// encoding/xml ignores unknown fields by default — forward-compatibility
// is structurally guaranteed for future schema additions.
//
// Canonical reference: /tmp/nmap-canonical-reference.xml from
// `nmap -sT -sV -oX -` execution (Nmap 7.94, xmloutputversion 1.05)
// against scanme.nmap.org. Fields surfaced in canonical output that
// are NOT in this v1 struct set (silently ignored by encoding/xml,
// preserved as forward-pinned additive enhancements):
//
//   - <cpe> child of <service> (M9 CVE-matching identifier; high-value)
//   - <service ostype/method/conf> attributes
//   - <service tunnel> attribute (TLS-wrapped service indicator)
//   - <hostnames><hostname.../></hostnames> (M8 recon-helper consumer)
//   - <extraports> element (aggregated closed-port count; informational)
//   - <hosthint>, <times>, <runstats>, <scaninfo>, <verbose>, <debugging>
//
// v1 preserves the host/port/protocol/state/service/product/version/
// extra_info/target subset in RawFinding.Metadata per Q6 lock.

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapStatus struct {
	State  string `xml:"state,attr"` // "up" | "down"
	Reason string `xml:"reason,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"` // "ipv4" | "ipv6" | "mac"
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"` // "tcp" | "udp" | "sctp"
	PortID   string      `xml:"portid,attr"`   // port number as string
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State  string `xml:"state,attr"` // "open" | "closed" | "filtered" | "open|filtered" | "closed|filtered"
	Reason string `xml:"reason,attr"`
}

type nmapService struct {
	Name      string   `xml:"name,attr"`
	Product   string   `xml:"product,attr,omitempty"`
	Version   string   `xml:"version,attr,omitempty"`
	ExtraInfo string   `xml:"extrainfo,attr,omitempty"`
	Tunnel    string   `xml:"tunnel,attr,omitempty"` // "ssl" when -sV detects TLS-wrapped service
	CPEs      []string `xml:"cpe"`                   // canonical NVD-queryable identifiers; multiple per service possible
	// Future additive: ostype, method, conf — forward-pinned for M9/M8 enhancement tasks
}

// parseOutput converts Nmap XML to RawFindings.
// One RawFinding per open port (per Q6 lock); closed/filtered ports
// not emitted (scan completeness data, not findings).
//
// target parameter is the original scan target (from DockerRunner.Run);
// used in Metadata.target for audit-log/abuse-detection downstream.
func parseOutput(stdout []byte, target string) ([]events.RawFinding, error) {
	var run nmapRun
	if err := xml.Unmarshal(stdout, &run); err != nil {
		return nil, fmt.Errorf("nmap: xml parse: %w", err)
	}

	var findings []events.RawFinding
	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue // host down or unknown; no port findings
		}
		hostAddr := primaryAddress(h.Addresses)
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue // closed/filtered/etc.; not emitted
			}
			findings = append(findings, buildFinding(hostAddr, p, target))
		}
	}
	return findings, nil
}

// primaryAddress selects the most useful address from a host's address list.
// Preference order: ipv4 > ipv6 > mac > first-available.
func primaryAddress(addrs []nmapAddress) string {
	var ipv4, ipv6, mac, fallback string
	for _, a := range addrs {
		if fallback == "" {
			fallback = a.Addr
		}
		switch a.AddrType {
		case "ipv4":
			if ipv4 == "" {
				ipv4 = a.Addr
			}
		case "ipv6":
			if ipv6 == "" {
				ipv6 = a.Addr
			}
		case "mac":
			if mac == "" {
				mac = a.Addr
			}
		}
	}
	if ipv4 != "" {
		return ipv4
	}
	if ipv6 != "" {
		return ipv6
	}
	if mac != "" {
		return mac
	}
	return fallback
}

// buildFinding constructs a RawFinding from a single open-port observation.
// Severity is always "info" — the lowercase shieldscan-api Severity enum
// value (the API's Pydantic Literal rejects "Informational"; the mixed-case
// spelling failed ingest validation). CVE matching + rule-based severity
// escalation are M9 + future-task concerns.
//
// FindingType ("open-port-<protocol>") and TargetURL ("host:port") are set
// here because ComputeFingerprint hashes tool|finding_type|target_url|...:
// with both empty, every nmap finding collapsed to the constant hash of
// "nmap|||||0". protocol distinguishes tcp/udp/sctp on the same host:port;
// host:port distinguishes ports and hosts.
func buildFinding(host string, p nmapPort, target string) events.RawFinding {
	return events.RawFinding{
		Title:       buildTitle(p),
		Severity:    "info",
		Description: buildDescription(host, p),
		FindingType: "open-port-" + p.Protocol,
		TargetURL:   buildTargetURL(host, p.PortID),
		Metadata:    buildMetadata(host, p, target),
		// Identity fields (ToolName, EngineCategory, DiscoveredAt, Fingerprint)
		// populated by DockerRunner enrichment loop per ToolRunner contract
		// (internal/tools/runner.go:65-69 docstring).
	}
}

// buildTargetURL builds the fingerprint-bearing target identifier for an
// open port as "host:port". IPv6 literal hosts are bracketed
// ("[2001:db8::1]:22") so the host/port colon boundary is unambiguous.
func buildTargetURL(host, port string) string {
	if strings.Contains(host, ":") { // IPv6 literal (or MAC fallback)
		return fmt.Sprintf("[%s]:%s", host, port)
	}
	return fmt.Sprintf("%s:%s", host, port)
}

func buildTitle(p nmapPort) string {
	service := p.Service.Name
	if service == "" {
		service = "unknown"
	}
	return fmt.Sprintf("Open port: %s/%s (%s)", p.PortID, p.Protocol, service)
}

func buildDescription(host string, p nmapPort) string {
	service := p.Service.Name
	if service == "" {
		service = "unidentified service"
	}

	desc := fmt.Sprintf("%s service detected on %s:%s.", service, host, p.PortID)

	if p.Service.Product != "" {
		desc += fmt.Sprintf(" Product: %s.", p.Service.Product)
	}
	if p.Service.Version != "" {
		desc += fmt.Sprintf(" Version: %s.", p.Service.Version)
	}
	if p.Service.ExtraInfo != "" {
		desc += fmt.Sprintf(" Extra info: %s.", p.Service.ExtraInfo)
	}

	return desc
}

func buildMetadata(host string, p nmapPort, target string) map[string]string {
	m := map[string]string{
		"host":     host,
		"port":     p.PortID,
		"protocol": p.Protocol,
		"state":    p.State.State,
		"service":  p.Service.Name,
		"target":   target,
	}
	// Conditional fields — only include if non-empty to keep Metadata clean
	if p.Service.Product != "" {
		m["product"] = p.Service.Product
	}
	if p.Service.Version != "" {
		m["version"] = p.Service.Version
	}
	if p.Service.ExtraInfo != "" {
		m["extra_info"] = p.Service.ExtraInfo
	}
	if p.Service.Tunnel != "" {
		m["tunnel"] = p.Service.Tunnel
	}
	if len(p.Service.CPEs) > 0 {
		m["cpe"] = strings.Join(p.Service.CPEs, ",")
	}
	return m
}
