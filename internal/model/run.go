package model

import "time"

type Producer struct{ Name, Version, Build string }
type PathSummary struct {
	Present, IsRoot             bool
	SegmentCount                uint64
	TrailingSlash, QueryPresent bool
}
type Target struct {
	Scheme, Hostname string
	EffectivePort    uint16
	Path             PathSummary
}
type Goal struct {
	Kind                   GoalKind
	ExpectationAssertionID *AssertionID
}
type RequestedScope struct{ Kind ScopeKind }
type Policy struct{ CoherenceWindowNS int64 }
type Capability struct {
	CapabilityID CapabilityID
	Kind         CapabilityKind
	State        CapabilityState
	ReasonCode   string
}
type LimitationScope struct {
	Kind          LimitationScopeKind
	VantageID     *VantageID
	ObservationID *ObservationID
	VisibilityID  *VisibilityID
	FindingID     *FindingID
}
type Limitation struct {
	LimitationID LimitationID
	Code         LimitationCode
	Scope        LimitationScope
}

type EvidenceRun struct {
	ReportSchemaVersion   SchemaVersion
	Producer              Producer
	RunID                 RunID
	Target                Target
	Goal                  Goal
	RequestedScope        RequestedScope
	Policy                Policy
	StartedAt             time.Time
	FinishedAt            time.Time
	VantagePoints         []VantagePoint
	Capabilities          []Capability
	OperatorAssertions    []OperatorAssertion
	Entities              []Entity
	ServicePath           ServicePath
	CheckDefinitions      []CheckDefinition
	CheckExecutions       []CheckExecution
	Observations          []Observation
	VisibilityAssessments []VisibilityAssessment
	Limitations           []Limitation
}

type EvaluatedRun struct {
	Evidence   EvidenceRun
	Evaluation Evaluation
	Claims     []Claim
	Findings   []Finding
}
type Evaluation struct {
	EvaluatedAt    time.Time
	OrderedRuleIDs []RuleID
}
