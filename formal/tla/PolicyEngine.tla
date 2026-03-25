--------------------------- MODULE PolicyEngine ----------------------------
(*
 * TLA+ formal model of the SentinelGate policy engine.
 *
 * Models three aspects of the Go implementation:
 *   1. Request evaluation: priority-ordered first-match-wins with default-deny
 *      (PolicyService.Evaluate in internal/service/policy_service.go)
 *   2. Hot-reload: atomic snapshot swap via atomic.Value concurrent with evaluation
 *      (PolicyService.Reload in internal/service/policy_service.go)
 *   3. Interceptor decision routing: deny blocks, allow/approval forwards
 *      (PolicyInterceptor.Intercept in internal/domain/proxy/policy_interceptor.go)
 *
 * Key Go patterns modeled:
 *   - atomic.Value for lock-free snapshot reads (loadSnapshot)
 *   - Priority-descending iteration with first-match-wins (Evaluate loop)
 *   - Compile-then-atomic-swap (Reload: compile outside lock, Store inside lock)
 *   - Default deny when no rule matches
 *)
EXTENDS Integers, Sequences, FiniteSets, TLC

\* ---------------------------------------------------------------------------
\* Constants (parameterised; concrete values supplied by MC_PolicyEngine)
\* ---------------------------------------------------------------------------

CONSTANTS
    Requests,           \* Set of request IDs
    Rules,              \* Set of rule IDs
    RulePriority,       \* Function: rule -> integer priority (higher = first)
    RuleAction,         \* Function: rule -> {"allow", "deny", "approval_required"}
    RuleMatches,        \* Function: <<rule, request>> -> BOOLEAN
    PolicySets,         \* Set of policy-set IDs (snapshots)
    PolicySetRules,     \* Function: policy_set -> SUBSET Rules
    InitialPolicySet    \* The policy set active at system start

\* ---------------------------------------------------------------------------
\* Variables
\* ---------------------------------------------------------------------------

VARIABLES
    request_state,      \* Function: request -> state string
    request_snapshot,   \* Function: request -> policy_set_id captured at eval start
    request_rule_idx,   \* Function: request -> 1-based index into sorted rules
    request_decision,   \* Function: request -> action string recorded at match time
    current_snapshot,   \* Currently active policy set (what loadSnapshot returns)
    reload_in_progress  \* BOOLEAN: whether a reload is in progress

vars == <<request_state, request_snapshot, request_rule_idx,
          request_decision, current_snapshot, reload_in_progress>>

\* ---------------------------------------------------------------------------
\* Helpers
\* ---------------------------------------------------------------------------

\* Set of valid request states
RequestStates == {"pending", "evaluating", "allowed", "denied",
                  "approval_required", "forwarded"}

\* Set of valid actions (what rules produce)
Actions == {"allow", "deny", "approval_required"}

\* Map action to request state (allow -> allowed, deny -> denied)
ActionToState(a) ==
    CASE a = "allow"             -> "allowed"
      [] a = "deny"              -> "denied"
      [] a = "approval_required" -> "approval_required"

\* Sort rules by descending priority (highest RulePriority first).
\* Returns a sequence of rules from the given set.
\* Uses a recursive selection-sort: repeatedly pick the highest-priority
\* element, append it, and recurse on the remainder.
\* Efficient enough for TLC on small sets (3-5 elements).
RECURSIVE SortedRulesRec(_)
SortedRulesRec(S) ==
    IF S = {} THEN << >>
    ELSE
        LET
            maxRule == CHOOSE x \in S :
                           \A y \in S : RulePriority[x] >= RulePriority[y]
        IN
            <<maxRule>> \o SortedRulesRec(S \ {maxRule})

SortedRules(ruleSet) == SortedRulesRec(ruleSet)

\* ---------------------------------------------------------------------------
\* Type invariant
\* ---------------------------------------------------------------------------

TypeOK ==
    /\ request_state     \in [Requests -> RequestStates]
    /\ request_snapshot  \in [Requests -> PolicySets \cup {"none"}]
    /\ request_rule_idx  \in [Requests -> 0..Cardinality(Rules)+1]
    /\ request_decision  \in [Requests -> Actions \cup {"none", "default_deny"}]
    /\ current_snapshot  \in PolicySets
    /\ reload_in_progress \in BOOLEAN

\* ---------------------------------------------------------------------------
\* Initial state
\* ---------------------------------------------------------------------------

Init ==
    /\ request_state     = [r \in Requests |-> "pending"]
    /\ request_snapshot  = [r \in Requests |-> "none"]
    /\ request_rule_idx  = [r \in Requests |-> 0]
    /\ request_decision  = [r \in Requests |-> "none"]
    /\ current_snapshot  = InitialPolicySet
    /\ reload_in_progress = FALSE

\* ---------------------------------------------------------------------------
\* Actions
\* ---------------------------------------------------------------------------

(*
 * StartEvaluation(r)
 * Models: PolicyService.Evaluate -> s.loadSnapshot() (atomic.Value load)
 * A pending request captures the current snapshot and begins evaluation.
 * Once captured, the request uses this snapshot for its entire evaluation,
 * regardless of any subsequent reloads.
 *)
StartEvaluation(r) ==
    /\ request_state[r] = "pending"
    /\ request_state'    = [request_state    EXCEPT ![r] = "evaluating"]
    /\ request_snapshot' = [request_snapshot EXCEPT ![r] = current_snapshot]
    /\ request_rule_idx' = [request_rule_idx EXCEPT ![r] = 1]
    /\ request_decision' = [request_decision EXCEPT ![r] = "none"]
    /\ UNCHANGED <<current_snapshot, reload_in_progress>>

(*
 * EvaluateRule(r)
 * Models: the for-loop in PolicyService.Evaluate iterating candidates in
 * priority order. Each step evaluates one rule.
 *
 * If the rule matches (RuleMatches) -> first-match-wins: record decision.
 * If the rule does not match -> advance index to next rule.
 *)
EvaluateRule(r) ==
    /\ request_state[r] = "evaluating"
    /\ LET
           ps    == request_snapshot[r]
           rules == SortedRules(PolicySetRules[ps])
           idx   == request_rule_idx[r]
       IN
           \* There is a rule to evaluate at this index
           /\ idx >= 1
           /\ idx <= Len(rules)
           /\ LET rule == rules[idx]
              IN
                  IF RuleMatches[rule, r]
                  THEN
                      \* First match wins: transition to terminal action state
                      /\ request_state'    = [request_state    EXCEPT ![r] =
                             ActionToState(RuleAction[rule])]
                      /\ request_decision' = [request_decision EXCEPT ![r] =
                             RuleAction[rule]]
                      /\ request_rule_idx' = [request_rule_idx EXCEPT ![r] =
                             idx]
                      /\ UNCHANGED <<request_snapshot, current_snapshot,
                                     reload_in_progress>>
                  ELSE
                      \* No match: advance to next rule
                      /\ request_rule_idx' = [request_rule_idx EXCEPT ![r] =
                             idx + 1]
                      /\ UNCHANGED <<request_state, request_snapshot,
                                     request_decision, current_snapshot,
                                     reload_in_progress>>

(*
 * DefaultDeny(r)
 * Models: the "default deny" path at the end of PolicyService.Evaluate
 * when no rule in the candidate list matched the request.
 *)
DefaultDeny(r) ==
    /\ request_state[r] = "evaluating"
    /\ LET
           ps    == request_snapshot[r]
           rules == SortedRules(PolicySetRules[ps])
           idx   == request_rule_idx[r]
       IN
           \* All rules exhausted (idx past the end)
           /\ idx > Len(rules)
           /\ request_state'    = [request_state    EXCEPT ![r] = "denied"]
           /\ request_decision' = [request_decision EXCEPT ![r] =
                  "default_deny"]
           /\ UNCHANGED <<request_snapshot, request_rule_idx,
                          current_snapshot, reload_in_progress>>

(*
 * ForwardAllowed(r)
 * Models: PolicyInterceptor.Intercept forwarding to next interceptor.
 *   - If decision.Allowed (action = "allow") -> forward to upstream
 *   - If decision.RequiresApproval (action = "approval_required") -> forward
 *     with decision in context for ApprovalInterceptor
 * In both cases the request reaches the "forwarded" state (passed through
 * the interceptor chain).
 *
 * A "denied" request is NEVER forwarded -- this is the safety property.
 *)
ForwardAllowed(r) ==
    /\ request_state[r] \in {"allowed", "approval_required"}
    /\ request_state' = [request_state EXCEPT ![r] = "forwarded"]
    /\ UNCHANGED <<request_snapshot, request_rule_idx, request_decision,
                   current_snapshot, reload_in_progress>>

(*
 * StartReload
 * Models: the beginning of PolicyService.Reload -- load from store, compile,
 * build index. All of this happens outside the lock.
 *)
StartReload ==
    /\ reload_in_progress = FALSE
    /\ reload_in_progress' = TRUE
    /\ UNCHANGED <<request_state, request_snapshot, request_rule_idx,
                   request_decision, current_snapshot>>

(*
 * CompleteReload(new_ps)
 * Models: the atomic snapshot swap in PolicyService.Reload:
 *   mu.Lock() -> snapshot.Store(new_snapshot) -> mu.Unlock()
 *
 * This is a single atomic step. Any request that subsequently calls
 * loadSnapshot() will see new_ps. Any request that already captured the
 * old snapshot via StartEvaluation continues with the old snapshot.
 *)
CompleteReload(new_ps) ==
    /\ reload_in_progress = TRUE
    /\ new_ps \in PolicySets
    /\ new_ps /= current_snapshot
    /\ current_snapshot'    = new_ps
    /\ reload_in_progress'  = FALSE
    /\ UNCHANGED <<request_state, request_snapshot, request_rule_idx,
                   request_decision>>

\* ---------------------------------------------------------------------------
\* Next-state relation
\* ---------------------------------------------------------------------------

Next ==
    \/ \E r \in Requests : StartEvaluation(r)
    \/ \E r \in Requests : EvaluateRule(r)
    \/ \E r \in Requests : DefaultDeny(r)
    \/ \E r \in Requests : ForwardAllowed(r)
    \/ StartReload
    \/ \E ps \in PolicySets : CompleteReload(ps)

\* ---------------------------------------------------------------------------
\* Fairness (needed for liveness)
\* ---------------------------------------------------------------------------

\* Weak fairness ensures enabled actions eventually execute.
\* WF on the disjunction of per-request actions ensures every request
\* that is evaluating eventually makes progress, and every allowed/approved
\* request is eventually forwarded.
Fairness ==
    /\ \A r \in Requests : WF_vars(EvaluateRule(r))
    /\ \A r \in Requests : WF_vars(DefaultDeny(r))
    /\ \A r \in Requests : WF_vars(ForwardAllowed(r))
    /\ \A r \in Requests : WF_vars(StartEvaluation(r))

\* ---------------------------------------------------------------------------
\* Specification
\* ---------------------------------------------------------------------------

Spec == Init /\ [][Next]_vars /\ Fairness

\* ---------------------------------------------------------------------------
\* Safety Invariants
\* ---------------------------------------------------------------------------

(*
 * SafetyInvariant
 * A request that was denied by a rule (or by default deny) is NEVER forwarded.
 * Equivalently: if a request is forwarded, it must have been matched by an
 * "allow" or "approval_required" rule.
 *
 * This models the Go code in PolicyInterceptor.Intercept:
 *   if !decision.Allowed && !decision.RequiresApproval { return PolicyDenyError }
 *)
SafetyInvariant ==
    \A r \in Requests :
        request_state[r] = "forwarded" =>
            request_decision[r] \in {"allow", "approval_required"}

(*
 * NoMixedPolicyInvariant
 * A request under evaluation always uses a single, valid policy set snapshot.
 * It never sees a mix of old and new rules.
 *
 * This models the Go code's atomic.Value pattern:
 *   snapshot := s.loadSnapshot()  -- captured once at evaluation start
 *   ... loop over snapshot.Index rules ...
 * The snapshot is immutable; reload creates a NEW snapshot object.
 *)
NoMixedPolicyInvariant ==
    \A r \in Requests :
        request_state[r] = "evaluating" =>
            /\ request_snapshot[r] \in PolicySets
            /\ request_snapshot[r] /= "none"

\* ---------------------------------------------------------------------------
\* Temporal Properties (Liveness)
\* ---------------------------------------------------------------------------

(*
 * LivenessProperty
 * Every request that starts pending eventually reaches a terminal state.
 * Terminal states: "denied" (blocked by policy or default deny),
 *                  "forwarded" (passed through interceptor chain).
 *
 * Uses the TLA+ leads-to (~>) operator.
 * Requires fairness assumptions (defined in Spec).
 *)
LivenessProperty ==
    \A r \in Requests :
        request_state[r] = "pending" ~>
            request_state[r] \in {"denied", "forwarded"}

============================================================================
