package compliance

// EUAIActTransparencyPack defines the EU AI Act Art. 13-15 requirements
// that SentinelGate can provide technical evidence for.
//
// Scope is intentionally limited to articles with direct technical evidence:
//   - Art. 13: Transparency — audit trail, decision logging
//   - Art. 14: Human oversight — intervention mechanisms, decision records
//   - Art. 15: Accuracy, robustness, cybersecurity — input validation, integrity checks
var EUAIActTransparencyPack = PolicyPack{
	ID:          "eu-ai-act-transparency",
	Name:        "EU AI Act — Transparency & Oversight (Art. 13-15)",
	Description: "Technical evidence for EU AI Act high-risk system requirements. Covers transparency of AI actions, human oversight mechanisms, and robustness measures.",
	Framework:   "EU AI Act",
	Version:     "1.0",
	Requirements: []Requirement{
		// Art. 13 — Transparency
		{
			ID:          "art-13-1",
			Article:     "Art. 13(1)",
			Title:       "Transparency — Operation Logging",
			Description: "High-risk AI systems shall be designed to enable operators to interpret the system's output and use it appropriately. Logging of all actions and decisions is required.",
			EvidenceChecks: []EvidenceCheck{
				{
					ID:          "art-13-1-audit-trail",
					Description: "Comprehensive audit trail of all AI tool invocations exists",
					CheckType:   CheckAuditTrailExists,
					Source:      "Audit Log",
				},
				{
					ID:          "art-13-1-decision-log",
					Description: "Policy decisions are logged with rule ID and reason for each action",
					CheckType:   CheckDecisionLogged,
					Source:      "Audit Log — Decision field",
				},
			},
		},
		{
			ID:          "art-13-2",
			Article:     "Art. 13(2)",
			Title:       "Transparency — Identity & Role Tracking",
			Description: "The system shall enable identification of the natural or legal person deploying and operating the AI system.",
			EvidenceChecks: []EvidenceCheck{
				{
					ID:          "art-13-2-identities",
					Description: "Identities with roles are configured for all AI agents",
					CheckType:   CheckIdentitiesConfigured,
					Source:      "Identity Management",
				},
			},
		},
		// Art. 14 — Human Oversight
		{
			ID:          "art-14-1",
			Article:     "Art. 14(1)",
			Title:       "Human Oversight — Intervention Capability",
			Description: "High-risk AI systems shall be designed to allow effective oversight by natural persons during the period of use.",
			EvidenceChecks: []EvidenceCheck{
				{
					ID:          "art-14-1-policies",
					Description: "Access control policies are configured to govern AI actions",
					CheckType:   CheckPoliciesConfigured,
					Source:      "Policy Engine",
				},
				{
					ID:          "art-14-1-hitl",
					Description: "Human-in-the-loop approval mechanism is available for sensitive actions",
					CheckType:   CheckHITLAvailable,
					Source:      "Approval System (HITL)",
				},
			},
		},
		{
			ID:          "art-14-4",
			Article:     "Art. 14(4)",
			Title:       "Human Oversight — Decision Audit Trail",
			Description: "Measures enabling oversight shall include the ability to correctly interpret the high-risk AI system's output.",
			EvidenceChecks: []EvidenceCheck{
				{
					ID:          "art-14-4-evidence-signed",
					Description: "Audit evidence is cryptographically signed for tamper-proof oversight",
					CheckType:   CheckEvidenceSigned,
					Source:      "Cryptographic Evidence",
				},
				{
					ID:          "art-14-4-decision-log",
					Description: "Decision rationale is recorded for each AI action",
					CheckType:   CheckDecisionLogged,
					Source:      "Audit Log — Reason field",
				},
			},
		},
		// Art. 15 — Accuracy, Robustness, Cybersecurity
		{
			ID:          "art-15-1",
			Article:     "Art. 15(1)",
			Title:       "Robustness — Input Validation",
			Description: "High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy, robustness, and cybersecurity.",
			EvidenceChecks: []EvidenceCheck{
				{
					ID:          "art-15-1-content-scan",
					Description: "Content scanning is enabled for input and response validation (PII, secrets, prompt injection)",
					CheckType:   CheckContentScanEnabled,
					Source:      "Content Scanning",
				},
				{
					ID:          "art-15-1-rate-limit",
					Description: "Rate limiting is configured to prevent abuse",
					CheckType:   CheckRateLimitEnabled,
					Source:      "Rate Limiter",
				},
			},
		},
		{
			ID:          "art-15-3",
			Article:     "Art. 15(3)",
			Title:       "Cybersecurity — Tool Integrity",
			Description: "High-risk AI systems shall be resilient regarding attempts by unauthorised third parties to alter their use or performance.",
			EvidenceChecks: []EvidenceCheck{
				{
					ID:          "art-15-3-tool-integrity",
					Description: "Tool integrity verification is enabled to detect tool definition tampering",
					CheckType:   CheckToolIntegrityEnabled,
					Source:      "Tool Integrity",
				},
			},
		},
	},
}

// BuiltinPacks contains all built-in policy packs.
var BuiltinPacks = map[string]*PolicyPack{
	EUAIActTransparencyPack.ID: &EUAIActTransparencyPack,
}
