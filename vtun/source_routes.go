package vtun

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// SourceRoute selects a preferred local source address for a destination
// prefix. VTun uses the route with the longest matching destination prefix.
type SourceRoute struct {
	// Destination is the remote prefix that selects Source. VTun masks this
	// prefix before it compares or installs the route.
	Destination netip.Prefix
	// Source is an address from Opts.LocalAddrs.
	Source netip.Addr
}

// sourceRouteState protects the source policy and serializes route updates
// with new transport flows. A connected endpoint keeps the route that gVisor
// selected during Connect, so later updates do not change an existing flow.
type sourceRouteState struct {
	sync.RWMutex
	routes       []SourceRoute
	hasIPv4Route bool
	hasIPv6Route bool
}

// normalizeSourceRoutes validates routes against the addresses assigned to the
// VTun. It also masks destination prefixes and removes exact duplicates.
func normalizeSourceRoutes(routes []SourceRoute, localAddrs []netip.Addr) ([]SourceRoute, error) {
	local := make(map[netip.Addr]struct{}, len(localAddrs))
	for _, addr := range localAddrs {
		local[addr] = struct{}{}
	}

	normalized := make([]SourceRoute, 0, len(routes))
	seen := make(map[netip.Prefix]netip.Addr, len(routes))
	for i, route := range routes {
		if !route.Destination.IsValid() {
			return nil, fmt.Errorf("source route %d: destination prefix is invalid", i)
		}
		if !route.Source.IsValid() {
			return nil, fmt.Errorf("source route %d: source address is invalid", i)
		}
		if route.Source.IsUnspecified() {
			return nil, fmt.Errorf("source route %d: source address %s is unspecified", i, route.Source)
		}
		if route.Source.IsMulticast() {
			return nil, fmt.Errorf("source route %d: source address %s is multicast", i, route.Source)
		}
		if route.Source.IsLoopback() {
			return nil, fmt.Errorf("source route %d: source address %s is loopback", i, route.Source)
		}
		if route.Destination.Addr().Is4() != route.Source.Is4() {
			return nil, fmt.Errorf(
				"source route %d: destination %s and source %s use different IP families",
				i, route.Destination, route.Source,
			)
		}
		if _, ok := local[route.Source]; !ok {
			return nil, fmt.Errorf(
				"source route %d: source address %s is not assigned to the VTun",
				i, route.Source,
			)
		}

		route.Destination = route.Destination.Masked()
		if previous, ok := seen[route.Destination]; ok {
			if previous != route.Source {
				return nil, fmt.Errorf(
					"source route %d: destination %s has conflicting source addresses %s and %s",
					i, route.Destination, previous, route.Source,
				)
			}
			continue
		}

		seen[route.Destination] = route.Source
		normalized = append(normalized, route)
	}
	return normalized, nil
}

func sourceRouteFamilies(routes []SourceRoute) (hasIPv4, hasIPv6 bool) {
	for _, route := range routes {
		if route.Destination.Addr().Is4() {
			hasIPv4 = true
		} else {
			hasIPv6 = true
		}
	}
	return hasIPv4, hasIPv6
}

// validateExplicitLocalAddr checks only specific local addresses. An invalid or
// unspecified address represents wildcard selection and does not override a
// source route.
func (vt *VTun) validateExplicitLocalAddr(local, remote netip.Addr) error {
	if !local.IsValid() || local.IsUnspecified() {
		return nil
	}
	if remote.IsValid() && local.Is4() != remote.Is4() {
		return fmt.Errorf("local address %s and remote address %s use different IP families", local, remote)
	}
	for _, assigned := range vt.localAddrs {
		if assigned == local {
			return nil
		}
	}
	return fmt.Errorf("local address %s is not assigned to the VTun", local)
}

// parseOptionalAddrPort accepts the address-only wildcard that runWithLookup
// produces for a dial without a requested local address.
func parseOptionalAddrPort(value string) (netip.AddrPort, error) {
	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		return addrPort, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, 0), nil
}

func sourceRouteTable(
	nicID tcpip.NICID,
	hasIPv4, hasIPv6 bool,
	routes []SourceRoute,
) ([]tcpip.Route, error) {
	hasIPv4Routes, hasIPv6Routes := sourceRouteFamilies(routes)
	table := make([]tcpip.Route, 0, len(routes)+2)

	for _, route := range routes {
		bits := route.Destination.Addr().BitLen()
		mask := net.CIDRMask(route.Destination.Bits(), bits)
		destination, err := tcpip.NewSubnet(
			tcpip.AddrFromSlice(route.Destination.Addr().AsSlice()),
			tcpip.MaskFromBytes(mask),
		)
		if err != nil {
			return nil, fmt.Errorf("convert source route destination %s: %w", route.Destination, err)
		}
		table = append(table, tcpip.Route{
			Destination: destination,
			NIC:         nicID,
			SourceHint:  tcpip.AddrFromSlice(route.Source.AsSlice()),
		})
	}

	// A family without a source policy keeps the legacy default route. A family
	// with a policy has no implicit fallback route.
	if hasIPv4 && !hasIPv4Routes {
		table = append(table, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	}
	if hasIPv6 && !hasIPv6Routes {
		table = append(table, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}
	return table, nil
}

func (vt *VTun) hasSourcePolicyLocked(isIPv6 bool) bool {
	if isIPv6 {
		return vt.sourceRoutes.hasIPv6Route
	}
	return vt.sourceRoutes.hasIPv4Route
}

// sourceForDestinationLocked returns the source from the longest matching
// prefix. Callers use this only for IPv6 because the current gVisor IPv6 source
// selector does not apply Route.SourceHint.
func (vt *VTun) sourceForDestinationLocked(destination netip.Addr) (netip.Addr, bool) {
	bestBits := -1
	var source netip.Addr
	for _, route := range vt.sourceRoutes.routes {
		if route.Destination.Bits() <= bestBits || !route.Destination.Contains(destination) {
			continue
		}
		bestBits = route.Destination.Bits()
		source = route.Source
	}
	return source, source.IsValid()
}

// SourceRoutes returns a copy of the active, normalized source-route table.
func (vt *VTun) SourceRoutes() []SourceRoute {
	vt.sourceRoutes.RLock()
	defer vt.sourceRoutes.RUnlock()
	return slices.Clone(vt.sourceRoutes.routes)
}

// SetSourceRoutes replaces the source-route table for new flows. The method
// validates the complete new table before it changes the active table. Existing
// TCP, connected UDP, and connected ICMP flows keep their selected sources.
func (vt *VTun) SetSourceRoutes(routes []SourceRoute) error {
	if err := vt.checkUp(); err != nil {
		return err
	}

	normalized, err := normalizeSourceRoutes(routes, vt.localAddrs)
	if err != nil {
		return err
	}
	table, err := sourceRouteTable(vt.nid, vt.hasV4, vt.hasV6, normalized)
	if err != nil {
		return err
	}
	hasIPv4Route, hasIPv6Route := sourceRouteFamilies(normalized)

	vt.sourceRoutes.Lock()
	defer vt.sourceRoutes.Unlock()
	vt.stack.SetRouteTable(table)
	vt.sourceRoutes.routes = normalized
	vt.sourceRoutes.hasIPv4Route = hasIPv4Route
	vt.sourceRoutes.hasIPv6Route = hasIPv6Route
	return nil
}
