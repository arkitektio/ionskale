package service

import (
	"context"
	"fmt"
	"github.com/bufbuild/connect-go"
	"github.com/jsiebens/ionscale/internal/config"
	"github.com/jsiebens/ionscale/internal/domain"
	api "github.com/jsiebens/ionscale/pkg/gen/ionscale/v1"
	"net/netip"
	"strings"
	"tailscale.com/util/dnsname"
)

func (s *Service) GetDNSConfig(ctx context.Context, req *connect.Request[api.GetDNSConfigRequest]) (*connect.Response[api.GetDNSConfigResponse], error) {
	principal := CurrentPrincipal(ctx)
	if !principal.IsSystemAdmin() && !principal.IsTailnetAdmin(req.Msg.TailnetId) {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied"))
	}

	tailnet, err := s.repository.GetTailnet(ctx, req.Msg.TailnetId)
	if err != nil {
		return nil, logError(err)
	}
	if tailnet == nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("tailnet not found"))
	}

	resp := &api.GetDNSConfigResponse{
		Config: domainDNSConfigToApiDNSConfig(tailnet),
	}

	return connect.NewResponse(resp), nil
}

func (s *Service) SetDNSConfig(ctx context.Context, req *connect.Request[api.SetDNSConfigRequest]) (*connect.Response[api.SetDNSConfigResponse], error) {
	principal := CurrentPrincipal(ctx)
	if !principal.IsSystemAdmin() && !principal.IsTailnetAdmin(req.Msg.TailnetId) {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied"))
	}

	dnsConfig := req.Msg.Config
	if dnsConfig == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("config is required"))
	}

	if err := validateDNSConfig(dnsConfig); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if dnsConfig.HttpsCerts && !dnsConfig.MagicDns {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("MagicDNS must be enabled when enabling HTTPS Certs"))
	}

	if dnsConfig.HttpsCerts && s.dnsProvider == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("A DNS provider must be configured when enabling HTTPS Certs"))
	}

	tailnet, err := s.repository.GetTailnet(ctx, req.Msg.TailnetId)
	if err != nil {
		return nil, logError(err)
	}
	if tailnet == nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("tailnet not found"))
	}

	oldConfig := tailnet.DNSConfig
	newConfig := apiDNSConfigToDomainDNSConfig(req.Msg.Config)

	if oldConfig.Equal(&newConfig) {
		return connect.NewResponse(&api.SetDNSConfigResponse{Config: domainDNSConfigToApiDNSConfig(tailnet)}), nil
	}

	tailnet.DNSConfig = newConfig
	if err := s.repository.SaveTailnet(ctx, tailnet); err != nil {
		return nil, logError(err)
	}

	s.sessionManager.NotifyAll(tailnet.ID)

	return connect.NewResponse(&api.SetDNSConfigResponse{Config: domainDNSConfigToApiDNSConfig(tailnet)}), nil
}

// validateDNSConfig checks the parts of a DNS config that would otherwise be
// pushed verbatim to every client: extra records need a valid FQDN, a
// supported type and an address matching that type. A nil config is valid
// (callers fall back to the defaults).
func validateDNSConfig(dnsConfig *api.DNSConfig) error {
	if dnsConfig == nil {
		return nil
	}
	for i, r := range dnsConfig.ExtraRecords {
		if r == nil {
			return fmt.Errorf("extra_records[%d]: record is empty", i)
		}
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("extra_records[%d]: name is required", i)
		}
		if err := dnsname.ValidHostname(r.Name); err != nil {
			return fmt.Errorf("extra_records[%d]: invalid name %q: %w", i, r.Name, err)
		}
		addr, err := netip.ParseAddr(r.Value)
		if err != nil {
			return fmt.Errorf("extra_records[%d] (%s): value %q is not an IP address", i, r.Name, r.Value)
		}
		switch strings.ToUpper(r.Type) {
		case "":
		case "A":
			if !addr.Is4() {
				return fmt.Errorf("extra_records[%d] (%s): an A record needs an IPv4 address", i, r.Name)
			}
		case "AAAA":
			if !addr.Is6() {
				return fmt.Errorf("extra_records[%d] (%s): an AAAA record needs an IPv6 address", i, r.Name)
			}
		default:
			return fmt.Errorf("extra_records[%d] (%s): unsupported type %q (A or AAAA)", i, r.Name, r.Type)
		}
	}
	return nil
}

func apiRecordsToDomainRecords(records []*api.DNSRecord) []domain.DNSRecord {
	if len(records) == 0 {
		return nil
	}
	result := make([]domain.DNSRecord, 0, len(records))
	for _, r := range records {
		if r == nil {
			continue
		}
		result = append(result, domain.DNSRecord{Name: r.Name, Type: strings.ToUpper(r.Type), Value: r.Value})
	}
	return result
}

func domainRecordsToApiRecords(records []domain.DNSRecord) []*api.DNSRecord {
	if len(records) == 0 {
		return nil
	}
	result := make([]*api.DNSRecord, 0, len(records))
	for _, r := range records {
		result = append(result, &api.DNSRecord{Name: r.Name, Type: r.Type, Value: r.Value})
	}
	return result
}

func domainRoutesToApiRoutes(routes map[string][]string) map[string]*api.Routes {
	var result = map[string]*api.Routes{}
	for k, v := range routes {
		result[k] = &api.Routes{Routes: v}
	}
	return result
}

func apiRoutesToDomainRoutes(routes map[string]*api.Routes) map[string][]string {
	var result = map[string][]string{}
	for k, v := range routes {
		result[k] = v.Routes
	}
	return result
}

func apiDNSConfigToDomainDNSConfig(dnsConfig *api.DNSConfig) domain.DNSConfig {
	if dnsConfig == nil {
		return domain.DNSConfig{}
	}

	return domain.DNSConfig{
		MagicDNS:          dnsConfig.MagicDns,
		HttpsCertsEnabled: dnsConfig.HttpsCerts,
		OverrideLocalDNS:  dnsConfig.OverrideLocalDns,
		Nameservers:       dnsConfig.Nameservers,
		Routes:            apiRoutesToDomainRoutes(dnsConfig.Routes),
		SearchDomains:     dnsConfig.SearchDomains,
		ExtraRecords:      apiRecordsToDomainRecords(dnsConfig.ExtraRecords),
	}
}

func domainDNSConfigToApiDNSConfig(tailnet *domain.Tailnet) *api.DNSConfig {
	tailnetDomain := domain.SanitizeTailnetName(tailnet.Name)
	dnsConfig := tailnet.DNSConfig
	return &api.DNSConfig{
		MagicDns:         dnsConfig.MagicDNS,
		HttpsCerts:       dnsConfig.HttpsCertsEnabled,
		MagicDnsSuffix:   fmt.Sprintf("%s.%s", tailnetDomain, config.MagicDNSSuffix()),
		OverrideLocalDns: dnsConfig.OverrideLocalDNS,
		Nameservers:      dnsConfig.Nameservers,
		Routes:           domainRoutesToApiRoutes(dnsConfig.Routes),
		SearchDomains:    dnsConfig.SearchDomains,
		ExtraRecords:     domainRecordsToApiRecords(dnsConfig.ExtraRecords),
	}
}
