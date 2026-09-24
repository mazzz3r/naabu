package result

import (
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result/confidence"
	"github.com/stretchr/testify/assert"
)

func TestAddPort(t *testing.T) {
	targetIP := "127.0.0.1"
	targetPort := &port.Port{Port: 8080, Protocol: protocol.TCP}
	targetPorts := map[string]*port.Port{targetPort.String(): targetPort}

	res := NewResult()
	res.AddPort(targetIP, targetPort)

	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, expectedIPS, res.ips)

	expectedIPSPorts := map[string]map[string]*port.Port{targetIP: targetPorts}
	assert.Equal(t, res.ipPorts, expectedIPSPorts)
}

func TestSetPorts(t *testing.T) {
	targetIP := "127.0.0.1"
	port80 := &port.Port{Port: 80, Protocol: protocol.TCP}
	port443 := &port.Port{Port: 443, Protocol: protocol.TCP}
	targetPorts := map[string]*port.Port{
		port80.String():  port80,
		port443.String(): port443,
	}

	res := NewResult()
	res.SetPorts(targetIP, []*port.Port{port80, port443})

	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, res.ips, expectedIPS)

	expectedIPSPorts := map[string]map[string]*port.Port{targetIP: targetPorts}
	assert.Equal(t, res.ipPorts, expectedIPSPorts)
}

func TestIPHasPort(t *testing.T) {
	targetIP := "127.0.0.1"
	expectedPort := &port.Port{Port: 8080, Protocol: protocol.TCP}
	unexpectedPort := &port.Port{Port: 8081, Protocol: protocol.TCP}

	res := NewResult()
	res.AddPort(targetIP, expectedPort)
	assert.True(t, res.IPHasPort(targetIP, expectedPort))
	assert.False(t, res.IPHasPort(targetIP, unexpectedPort))
}

func TestUpdatePortService(t *testing.T) {
	targetIP := "127.0.0.1"
	stored := &port.Port{Port: 80, Protocol: protocol.TCP}
	service := &port.Service{Name: "http"}

	res := NewResult()
	res.AddPort(targetIP, stored)

	assert.True(t, res.UpdatePortService(targetIP, &port.Port{Port: 80, Protocol: protocol.TCP, Service: service}))
	assert.Equal(t, service, stored.Service)

	// same number, other protocol: the port exists but keeps its service info
	assert.True(t, res.UpdatePortService(targetIP, &port.Port{Port: 80, Protocol: protocol.UDP, Service: &port.Service{Name: "dns"}}))
	assert.Equal(t, service, stored.Service)

	assert.False(t, res.UpdatePortService(targetIP, &port.Port{Port: 81, Protocol: protocol.TCP, Service: service}))
	assert.False(t, res.UpdatePortService("127.0.0.2", &port.Port{Port: 80, Protocol: protocol.TCP, Service: service}))
}

func TestAddIP(t *testing.T) {
	targetIP := "127.0.0.1"

	res := NewResult()
	res.AddIp(targetIP)
	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, res.ips, expectedIPS)
}

func TestHasIP(t *testing.T) {
	targetIP := "127.0.0.1"

	res := NewResult()
	res.AddIp(targetIP)
	assert.True(t, res.HasIP(targetIP))
	assert.False(t, res.HasIP("1.2.3.4"))
}

func TestDeadHosts(t *testing.T) {
	res := NewResult()
	assert.False(t, res.HasDeadHosts())

	res.AddDeadHost("10.0.0.1")
	res.AddDeadHost("10.0.0.2")
	// adding the same host again must not duplicate it
	res.AddDeadHost("10.0.0.1")

	assert.True(t, res.HasDeadHosts())
	assert.ElementsMatch(t, []string{"10.0.0.1", "10.0.0.2"}, res.GetDeadHosts())
}

func TestMACAddress(t *testing.T) {
	res := NewResult()
	assert.Empty(t, res.GetMACAddress("10.0.0.1"))

	res.SetMACAddress("10.0.0.1", "aa:bb:cc:dd:ee:ff")
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", res.GetMACAddress("10.0.0.1"))

	// empty MAC values are ignored and never overwrite an existing entry
	res.SetMACAddress("10.0.0.1", "")
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", res.GetMACAddress("10.0.0.1"))
}

// runWithTimeout fails the test instead of hanging forever when fn deadlocks.
func runWithTimeout(t *testing.T, fn func()) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock: timed out while ranging over results")
	}
}

func TestGetIPsReentrant(t *testing.T) {
	res := NewResult()
	targetIPs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for _, ip := range targetIPs {
		res.AddIp(ip)
		res.SetMACAddress(ip, "aa:bb:cc:dd:ee:ff")
	}

	var got []string
	runWithTimeout(t, func() {
		for ip := range res.GetIPs() {
			// readers and writers on the same result must not block while
			// the consumer is still ranging (mirrors handleOutput in -sn mode)
			assert.True(t, res.HasIP(ip))
			assert.Equal(t, "aa:bb:cc:dd:ee:ff", res.GetMACAddress(ip))
			res.AddDeadHost(ip)
			got = append(got, ip)
		}
	})
	assert.ElementsMatch(t, targetIPs, got)
}

func TestGetIPsPortsReentrant(t *testing.T) {
	res := NewResult()
	// non-private ips so that no ARP lookup is attempted
	targetIPs := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	targetPort := &port.Port{Port: 80, Protocol: protocol.TCP}
	for _, ip := range targetIPs {
		res.AddPort(ip, targetPort)
	}
	res.AddSkipped("192.0.2.2")

	var got []string
	runWithTimeout(t, func() {
		for hostResult := range res.GetIPsPorts() {
			assert.True(t, res.IPHasPort(hostResult.IP, targetPort))
			if hostResult.IP == "192.0.2.2" {
				assert.Equal(t, confidence.Low, hostResult.Confidence)
			} else {
				assert.Equal(t, confidence.Normal, hostResult.Confidence)
			}
			res.AddPort(hostResult.IP, &port.Port{Port: 443, Protocol: protocol.TCP})
			got = append(got, hostResult.IP)
		}
	})
	assert.ElementsMatch(t, targetIPs, got)
}

func TestGetIPsPortsEarlyReturn(t *testing.T) {
	res := NewResult()
	// non-private ips so that no ARP lookup is attempted
	targetIPs := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	for _, ip := range targetIPs {
		res.AddPort(ip, &port.Port{Port: 80, Protocol: protocol.TCP})
	}

	// consumers like UpdateHostOS stop after the first match; the producer
	// must still run to completion instead of blocking forever on send
	out := res.GetIPsPorts()
	<-out
	assert.Eventually(t, func() bool {
		return len(out) == len(targetIPs)-1
	}, 5*time.Second, 10*time.Millisecond)
}

func TestUpdateHostOS(t *testing.T) {
	res := NewResult()
	p := &port.Port{Port: 22, Protocol: protocol.TCP}
	res.AddPort("192.0.2.1", p)
	res.AddPort("192.0.2.2", p)

	osfp := &OSFingerprint{Target: "192.0.2.1", OSDetails: "Linux 5.x"}
	res.UpdateHostOS("192.0.2.1", osfp)
	// nil must not clear existing info
	res.UpdateHostOS("192.0.2.1", nil)

	got := make(map[string]*OSFingerprint)
	for hostResult := range res.GetIPsPorts() {
		got[hostResult.IP] = hostResult.OS
	}

	assert.Len(t, got, 2)
	assert.Equal(t, osfp, got["192.0.2.1"])
	assert.Nil(t, got["192.0.2.2"])
}
