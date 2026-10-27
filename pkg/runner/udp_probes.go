package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint/udp"
)

// loadProbeDB parses the nmap-service-probes file at path the first
// time it is asked and memoises the result on the runner, so a follow
// up call from a different feature (e.g. -uP after -sV) reuses the
// already-parsed database instead of paying the parse cost twice.
func (r *Runner) loadProbeDB(path string) (*fingerprint.ProbeDB, error) {
	if r.probeDB != nil {
		return r.probeDB, nil
	}
	db, err := fingerprint.ParseProbeFile(path)
	if err != nil {
		return nil, err
	}
	gologger.Debug().Msgf("Loaded %d probes from %s", len(db.Probes), path)
	r.probeDB = db
	return db, nil
}

// udpProbeAdapter satisfies scan.UDPProbeProvider from two independent sources:
// the native UDP engine's built-in payloads (nmap-independent) and, when
// available, the nmap-service-probes database. The built-in payloads win for
// the ports they cover; the nmap database fills in the long tail. Keeping the
// adapter in the runner package avoids pulling pkg/fingerprint into pkg/scan
// and the import cycle that would imply.
type udpProbeAdapter struct {
	builtin *udp.Engine
	db      *fingerprint.ProbeDB
}

func (a udpProbeAdapter) UDPProbe(port int) []byte {
	if a.builtin != nil {
		if payload := a.builtin.UDPProbe(port); len(payload) > 0 {
			return payload
		}
	}
	if a.db != nil {
		return a.db.UDPProbeForPort(port)
	}
	return nil
}

// initUDPProbes wires per-port UDP payloads into the scanner so a UDP port scan
// elicits responses from otherwise-silent services. The feature is opt-in via
// -uP; when disabled the call is a no-op and UDP scanning keeps its historical
// empty-payload behavior.
//
// Unlike before, -uP no longer requires nmap: the native UDP engine supplies
// built-in payloads for every protocol it knows. A local nmap-service-probes
// file, when present, is layered on top to cover additional ports.
//
// The provider is reset on the scanner up-front so a previous
// SetUDPProbeProvider call on this scanner cannot leak into a follow up run that
// no longer wants probing.
func (r *Runner) initUDPProbes() {
	if r.scanner == nil {
		return
	}
	r.scanner.SetUDPProbeProvider(nil)
	// Built-in payloads are installed for explicit -uP and, implicitly, for -sV:
	// a UDP port is only reported open when it answers, which needs a protocol
	// payload, so service detection would otherwise find nothing to probe.
	if !r.options.UDPProbes && !r.options.ServiceVersion {
		return
	}

	adapter := udpProbeAdapter{builtin: r.ensureUDPEngine()}

	probeFile := r.options.ServiceProbesFile
	if probeFile == "" {
		probeFile = fingerprint.LocateNmapProbes()
	}
	if probeFile != "" {
		if db, err := r.loadProbeDB(probeFile); err != nil {
			gologger.Warning().Msgf("could not load service probes from %s for -uP, using built-in payloads only: %s", probeFile, err)
		} else {
			adapter.db = db
		}
	}

	r.scanner.SetUDPProbeProvider(adapter)
}
