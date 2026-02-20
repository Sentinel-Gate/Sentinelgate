package action

// DefaultBlocklistRules returns the default outbound blocklist rules active on
// a fresh SentinelGate installation. These rules block common data exfiltration
// channels and access to private/internal networks.
func DefaultBlocklistRules() []OutboundRule {
	return []OutboundRule{
		{
			ID:       "default-blocklist-1",
			Name:     "Data Exfiltration Services",
			Mode:     RuleModeBlocklist,
			Action:   RuleActionBlock,
			Enabled:  false,
			Priority: 100,
			Targets: []OutboundTarget{
				// Telegram
				{Type: TargetDomainGlob, Value: "*.telegram.org"},
				{Type: TargetDomain, Value: "t.me"},
				// ngrok tunnels
				{Type: TargetDomainGlob, Value: "*.ngrok.io"},
				{Type: TargetDomainGlob, Value: "*.ngrok-free.app"},
				// SSH tunneling
				{Type: TargetDomain, Value: "serveo.net"},
				// Cloudflare tunnels
				{Type: TargetDomainGlob, Value: "*.trycloudflare.com"},
				// Paste services
				{Type: TargetDomain, Value: "pastebin.com"},
				{Type: TargetDomainGlob, Value: "*.pastebin.com"},
				{Type: TargetDomain, Value: "hastebin.com"},
				// Request inspection
				{Type: TargetDomainGlob, Value: "*.requestbin.com"},
				{Type: TargetDomainGlob, Value: "*.pipedream.com"},
			},
			HelpText: "This destination is blocked by the default security policy. Data exfiltration services are blocked to prevent unauthorized data leakage. Edit outbound rules in Admin UI > Security > Outbound Control to customize.",
			HelpURL:  "/admin/#/security/outbound",
		},
		{
			ID:       "default-blocklist-2",
			Name:     "Private Network Access",
			Mode:     RuleModeBlocklist,
			Action:   RuleActionBlock,
			Enabled:  false,
			Priority: 200,
			Targets: []OutboundTarget{
				// IPv4 loopback
				{Type: TargetCIDR, Value: "127.0.0.0/8"},
				// Private class A
				{Type: TargetCIDR, Value: "10.0.0.0/8"},
				// Private class B
				{Type: TargetCIDR, Value: "172.16.0.0/12"},
				// Private class C
				{Type: TargetCIDR, Value: "192.168.0.0/16"},
				// Link-local
				{Type: TargetCIDR, Value: "169.254.0.0/16"},
				// IPv6 loopback (future-proofing)
				{Type: TargetCIDR, Value: "::1/128"},
			},
			HelpText: "This destination is blocked by the default security policy. Access to private/internal networks from agent actions is restricted. Edit outbound rules in Admin UI > Security > Outbound Control to customize.",
			HelpURL:  "/admin/#/security/outbound",
		},
	}
}
