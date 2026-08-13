package nmap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadFixture reads a testdata XML fixture file.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "fixture load: %s", path)
	return data
}

func TestParseOutput_TypicalWebServer(t *testing.T) {
	xml := loadFixture(t, "typical-web-server.xml")

	findings, err := parseOutput(xml, "192.0.2.10")
	require.NoError(t, err)
	assert.Len(t, findings, 4, "typical web server fixture has 4 open ports")

	for _, f := range findings {
		assert.Equal(t, "info", f.Severity)
	}

	require.NotEmpty(t, findings[0].Metadata)
	assert.Equal(t, "192.0.2.10", findings[0].Metadata["host"])
	assert.Contains(t, findings[0].Metadata, "service")
	assert.Equal(t, "192.0.2.10", findings[0].Metadata["target"])
}

func TestParseOutput_EmptyResult(t *testing.T) {
	xml := loadFixture(t, "empty-result.xml")

	findings, err := parseOutput(xml, "192.0.2.20")
	require.NoError(t, err, "empty result is valid; not an error")
	assert.Empty(t, findings, "no open ports → no findings")
}

func TestParseOutput_PartialHostTimeout(t *testing.T) {
	xml := loadFixture(t, "partial-host-timeout.xml")

	findings, err := parseOutput(xml, "192.0.2.30")
	require.NoError(t, err)
	for _, f := range findings {
		require.NotEmpty(t, f.Metadata["host"])
	}
}

func TestParseOutput_MalformedXML(t *testing.T) {
	xml := loadFixture(t, "malformed.xml")

	_, err := parseOutput(xml, "192.0.2.40")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "xml parse")
}

func TestParseOutput_ServiceWithoutVersion(t *testing.T) {
	xml := loadFixture(t, "service-detected-no-version.xml")

	findings, err := parseOutput(xml, "192.0.2.50")
	require.NoError(t, err)
	require.Len(t, findings, 1)

	desc := findings[0].Description
	assert.Contains(t, desc, "service detected")
	assert.NotContains(t, desc, "Product:")
	assert.NotContains(t, desc, "Version:")

	assert.NotContains(t, findings[0].Metadata, "product")
	assert.NotContains(t, findings[0].Metadata, "version")
}

func TestParseOutput_MultiHostMixed(t *testing.T) {
	xml := loadFixture(t, "multi-host-mixed.xml")

	findings, err := parseOutput(xml, "test.invalid")
	require.NoError(t, err)
	// host A (198.51.100.1, up) has 1 open port; host B (down) skipped;
	// host C (up but all closed) produces no findings
	require.Len(t, findings, 1)
	assert.Equal(t, "198.51.100.1", findings[0].Metadata["host"])
}

func TestParseOutput_UnknownFieldsIgnored(t *testing.T) {
	xml := loadFixture(t, "unknown-fields.xml")

	findings, err := parseOutput(xml, "192.0.2.60")
	require.NoError(t, err, "unknown XML fields must be silently ignored")
	require.Len(t, findings, 1, "fixture has one open port")
	assert.Equal(t, "http", findings[0].Metadata["service"])
}

func TestParseOutput_SkipsClosedPorts(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.70" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	findings, err := parseOutput(xml, "192.0.2.70")
	require.NoError(t, err)
	require.Len(t, findings, 1, "only open port produces finding")
	assert.Equal(t, "22", findings[0].Metadata["port"])
}

func TestParseOutput_SkipsFilteredPorts(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.71" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="filtered"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	findings, err := parseOutput(xml, "192.0.2.71")
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParseOutput_SkipsOpenFilteredPorts(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.72" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open|filtered"/>
        <service name="snmp"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	findings, err := parseOutput(xml, "192.0.2.72")
	require.NoError(t, err)
	assert.Empty(t, findings, "open|filtered ambiguous state not emitted")
}

func TestParseOutput_SkipsDownHosts(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
    <address addr="192.0.2.80" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	findings, err := parseOutput(xml, "192.0.2.80")
	require.NoError(t, err)
	assert.Empty(t, findings, "down hosts produce zero findings even with open-port elements")
}

func TestPrimaryAddress_PrefersIPv4(t *testing.T) {
	addrs := []nmapAddress{
		{Addr: "00:11:22:33:44:55", AddrType: "mac"},
		{Addr: "2001:db8::1", AddrType: "ipv6"},
		{Addr: "192.0.2.100", AddrType: "ipv4"},
	}
	assert.Equal(t, "192.0.2.100", primaryAddress(addrs))
}

func TestPrimaryAddress_FallsBackToIPv6(t *testing.T) {
	addrs := []nmapAddress{
		{Addr: "2001:db8::1", AddrType: "ipv6"},
		{Addr: "00:11:22:33:44:55", AddrType: "mac"},
	}
	assert.Equal(t, "2001:db8::1", primaryAddress(addrs))
}

func TestPrimaryAddress_FallsBackToMAC(t *testing.T) {
	addrs := []nmapAddress{
		{Addr: "00:11:22:33:44:55", AddrType: "mac"},
	}
	assert.Equal(t, "00:11:22:33:44:55", primaryAddress(addrs))
}

func TestPrimaryAddress_EmptyReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", primaryAddress(nil))
}

func TestBuildTitle_KnownService(t *testing.T) {
	p := nmapPort{
		Protocol: "tcp",
		PortID:   "22",
		Service:  nmapService{Name: "ssh"},
	}
	assert.Equal(t, "Open port: 22/tcp (ssh)", buildTitle(p))
}

func TestBuildTitle_UnknownService(t *testing.T) {
	p := nmapPort{
		Protocol: "tcp",
		PortID:   "9999",
		Service:  nmapService{Name: ""},
	}
	assert.Equal(t, "Open port: 9999/tcp (unknown)", buildTitle(p))
}

func TestBuildDescription_FullMetadata(t *testing.T) {
	p := nmapPort{
		PortID: "22",
		Service: nmapService{
			Name: "ssh", Product: "OpenSSH", Version: "8.9p1", ExtraInfo: "Ubuntu 3ubuntu0.4",
		},
	}
	desc := buildDescription("192.0.2.10", p)
	assert.Contains(t, desc, "ssh service detected on 192.0.2.10:22")
	assert.Contains(t, desc, "Product: OpenSSH")
	assert.Contains(t, desc, "Version: 8.9p1")
	assert.Contains(t, desc, "Extra info: Ubuntu 3ubuntu0.4")
}

func TestBuildDescription_MinimalMetadata(t *testing.T) {
	p := nmapPort{
		PortID:  "22",
		Service: nmapService{Name: "ssh"},
	}
	desc := buildDescription("192.0.2.10", p)
	assert.Contains(t, desc, "ssh service detected on 192.0.2.10:22")
	assert.NotContains(t, desc, "Product:")
	assert.NotContains(t, desc, "Version:")
	assert.NotContains(t, desc, "Extra info:")
}

func TestBuildMetadata_RequiredKeys(t *testing.T) {
	p := nmapPort{
		Protocol: "tcp", PortID: "22",
		State:   nmapState{State: "open"},
		Service: nmapService{Name: "ssh"},
	}
	m := buildMetadata("192.0.2.10", p, "192.0.2.10")
	for _, key := range []string{"host", "port", "protocol", "state", "service", "target"} {
		assert.Contains(t, m, key, "required key missing: %s", key)
	}
}

func TestBuildMetadata_ConditionalKeys(t *testing.T) {
	p := nmapPort{
		PortID:  "22",
		Service: nmapService{Name: "ssh", Product: "OpenSSH", Version: "8.9p1"},
	}
	m := buildMetadata("192.0.2.10", p, "192.0.2.10")
	assert.Contains(t, m, "product")
	assert.Contains(t, m, "version")

	p2 := nmapPort{
		PortID:  "22",
		Service: nmapService{Name: "ssh"},
	}
	m2 := buildMetadata("192.0.2.10", p2, "192.0.2.10")
	assert.NotContains(t, m2, "product")
	assert.NotContains(t, m2, "version")
}

func TestBuildMetadata_CPEs(t *testing.T) {
	p := nmapPort{
		PortID: "22",
		Service: nmapService{
			Name: "ssh",
			CPEs: []string{"cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"},
		},
	}
	m := buildMetadata("192.0.2.10", p, "192.0.2.10")
	assert.Equal(t, "cpe:/a:openbsd:openssh:8.9p1,cpe:/o:linux:linux_kernel", m["cpe"])
}

func TestBuildMetadata_NoCPEsWhenEmpty(t *testing.T) {
	p := nmapPort{
		PortID:  "22",
		Service: nmapService{Name: "ssh", CPEs: nil},
	}
	m := buildMetadata("192.0.2.10", p, "192.0.2.10")
	assert.NotContains(t, m, "cpe")
}

func TestBuildMetadata_Tunnel(t *testing.T) {
	p := nmapPort{
		PortID: "443",
		Service: nmapService{
			Name:    "https",
			Product: "nginx",
			Version: "1.18.0",
			Tunnel:  "ssl",
		},
	}
	m := buildMetadata("192.0.2.10", p, "192.0.2.10")
	assert.Equal(t, "ssl", m["tunnel"])
}

func TestBuildMetadata_NoTunnelWhenEmpty(t *testing.T) {
	p := nmapPort{
		PortID:  "80",
		Service: nmapService{Name: "http", Tunnel: ""},
	}
	m := buildMetadata("192.0.2.10", p, "192.0.2.10")
	assert.NotContains(t, m, "tunnel")
}

// TestParseOutput_FingerprintInputsAreDistinct pins the fix for the
// collapsed-fingerprint bug: every nmap finding used to hash to the
// constant SHA256("nmap|||||0") because parseOutput set neither
// FindingType nor TargetURL. With FindingType="open-port-<proto>" and
// TargetURL="host:port", the three ways open ports differ each yield a
// distinct fingerprint:
//   - two ports on one host      (192.0.2.1:22 vs :80)   — TargetURL
//   - same port on two hosts     (192.0.2.1:22 vs .2:22) — TargetURL
//   - same host+port, other proto (192.0.2.1:80 tcp/udp) — FindingType
func TestParseOutput_FingerprintInputsAreDistinct(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="udp" portid="80"><state state="open"/><service name="http"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.0.2.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
</nmaprun>`)

	findings, err := parseOutput(xml, "test.invalid")
	require.NoError(t, err)
	require.Len(t, findings, 4, "3 open ports on host A + 1 on host B")

	fps := make(map[string]struct{})
	for _, f := range findings {
		assert.Equal(t, "info", f.Severity, "lowercase api Severity enum value")
		require.NotEmpty(t, f.FindingType, "FindingType must feed the fingerprint")
		require.NotEmpty(t, f.TargetURL, "TargetURL must feed the fingerprint")
		f.ToolName = "nmap" // mirror the DockerRunner enrichment step
		fps[tools.ComputeFingerprint(f)] = struct{}{}
	}
	assert.Len(t, fps, 4, "each open port must fingerprint distinctly, not collapse to one")
}

func TestBuildTargetURL(t *testing.T) {
	assert.Equal(t, "192.0.2.1:22", buildTargetURL("192.0.2.1", "22"))
	assert.Equal(t, "[2001:db8::1]:443", buildTargetURL("2001:db8::1", "443"),
		"IPv6 literal host must be bracketed")
}

func TestParseOutput_UnknownFieldsXMLCapturesCPE(t *testing.T) {
	xml := loadFixture(t, "unknown-fields.xml")
	findings, err := parseOutput(xml, "192.0.2.60")
	require.NoError(t, err)
	require.NotEmpty(t, findings, "fixture has at least one open port")

	// unknown-fields.xml fixture includes <cpe> elements; verify capture
	foundCPE := false
	for _, f := range findings {
		if cpe, ok := f.Metadata["cpe"]; ok && cpe != "" {
			foundCPE = true
			break
		}
	}
	assert.True(t, foundCPE, "unknown-fields.xml has <cpe> elements; should now be captured")
}
