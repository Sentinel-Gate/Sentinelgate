------------------------- MODULE MC_PolicyEngine ---------------------------
(*
 * Model-checking module for PolicyEngine.tla
 *
 * Provides concrete finite constants for TLC to explore the state space.
 * Uses string literals instead of model values so TLC can enumerate
 * quantifier bounds in temporal formulas (LivenessProperty uses ~>).
 *
 * Test scenario:
 *   - 2 requests: "r1", "r2"
 *   - 3 rules: "rule1" (deny, p=200), "rule2" (allow, p=100), "rule3" (approval, p=50)
 *   - 2 policy sets: "ps_old" (all 3 rules), "ps_new" ("rule2" + "rule3" only)
 *
 * Key scenario: "r1" matches "rule1" (deny) in "ps_old". After reload to "ps_new"
 * (where "rule1" is removed), "r1" matches "rule2" (allow). During reload, any
 * request that already captured "ps_old" continues to be denied (hot-reload
 * atomicity).
 *)
EXTENDS PolicyEngine

\* ---------------------------------------------------------------------------
\* Concrete constant definitions (string literals for TLC enumerability)
\* ---------------------------------------------------------------------------

MCRequests == {"r1", "r2"}

MCRules == {"rule1", "rule2", "rule3"}

\* Priority: rule1(200) > rule2(100) > rule3(50)
\* Higher number = evaluated first (matches Go sort descending)
MCRulePriority == ("rule1" :> 200) @@ ("rule2" :> 100) @@ ("rule3" :> 50)

\* Actions: deny at highest priority, allow at medium, approval at lowest
MCRuleAction == ("rule1" :> "deny") @@ ("rule2" :> "allow") @@ ("rule3" :> "approval_required")

\* Match function: which rules match which requests
\* - rule1 matches r1 only (targeted deny)
\* - rule2 matches both r1 and r2 (broad allow)
\* - rule3 matches r2 only (approval for r2)
\*
\* Under ps_old (has all rules):
\*   r1: matches rule1 (deny, p=200) first -> denied
\*   r2: matches rule2 (allow, p=100) first -> allowed (rule3 also matches but lower priority)
\*
\* Under ps_new (rule1 removed):
\*   r1: matches rule2 (allow, p=100) -> allowed (deny rule gone)
\*   r2: matches rule2 (allow, p=100) -> allowed
MCRuleMatches ==
    (<<"rule1", "r1">> :> TRUE)  @@ (<<"rule1", "r2">> :> FALSE) @@
    (<<"rule2", "r1">> :> TRUE)  @@ (<<"rule2", "r2">> :> TRUE)  @@
    (<<"rule3", "r1">> :> FALSE) @@ (<<"rule3", "r2">> :> TRUE)

MCPolicySets == {"ps_old", "ps_new"}

\* ps_old has all 3 rules; ps_new removes the deny rule (rule1)
MCPolicySetRules == ("ps_old" :> {"rule1", "rule2", "rule3"}) @@ ("ps_new" :> {"rule2", "rule3"})

MCInitialPolicySet == "ps_old"

\* ---------------------------------------------------------------------------
\* Override temporal formulas with explicit enumeration for TLC.
\* TLC cannot enumerate CONSTANT-defined sets in temporal quantifiers,
\* so we expand them manually here.
\* ---------------------------------------------------------------------------

MCFairness ==
    /\ WF_vars(EvaluateRule("r1"))
    /\ WF_vars(EvaluateRule("r2"))
    /\ WF_vars(DefaultDeny("r1"))
    /\ WF_vars(DefaultDeny("r2"))
    /\ WF_vars(ForwardAllowed("r1"))
    /\ WF_vars(ForwardAllowed("r2"))
    /\ WF_vars(StartEvaluation("r1"))
    /\ WF_vars(StartEvaluation("r2"))

MCSpec == Init /\ [][Next]_vars /\ MCFairness

MCLivenessProperty ==
    /\ (request_state["r1"] = "pending" ~> request_state["r1"] \in {"denied", "forwarded"})
    /\ (request_state["r2"] = "pending" ~> request_state["r2"] \in {"denied", "forwarded"})

============================================================================
