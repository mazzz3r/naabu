// Package services wires every UDP protocol plugin into a single list the UDP
// engine is built from. Registration is explicit (no init-time global state),
// so the set of plugins is a plain, reviewable slice.
package services

import (
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/bacnet"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/coap"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/dhcp"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/dns"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/ethercat"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/gtpc"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/gtpprime"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/gtpu"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/iax2"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/ikev2"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/ipmi"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/ipsec"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/knxip"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/l2tp"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/lwm2m"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/megaco"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/mgcp"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/netbios"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/nfs"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/ntp"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/omronfins"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/openvpn"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/pcanywhere"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/pfcp"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/quic"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/rdpeudp"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/sip"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/smbudp"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/snmp"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/stun"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/tftp"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/turn"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp/services/wireguard"
)

// All returns one instance of every UDP plugin. The engine sorts them by
// priority and indexes them by port.
func All() []udp.Plugin {
	return []udp.Plugin{
		dns.Plugin{},
		ntp.Plugin{},
		snmp.Plugin{},
		ipmi.Plugin{},
		ipsec.Plugin{},
		ikev2.Plugin{},
		openvpn.Plugin{},
		wireguard.Plugin{},
		netbios.Plugin{},
		l2tp.Plugin{},
		dhcp.Plugin{},
		tftp.Plugin{},
		nfs.Plugin{},
		sip.Plugin{},
		coap.Plugin{},
		lwm2m.Plugin{},
		stun.Plugin{},
		turn.Plugin{},
		mgcp.Plugin{},
		megaco.Plugin{},
		iax2.Plugin{},
		gtpc.Plugin{},
		gtpu.Plugin{},
		gtpprime.Plugin{},
		pfcp.Plugin{},
		bacnet.Plugin{},
		knxip.Plugin{},
		ethercat.Plugin{},
		omronfins.Plugin{},
		rdpeudp.Plugin{},
		pcanywhere.Plugin{},
		quic.Plugin{},
		smbudp.Plugin{},
	}
}
