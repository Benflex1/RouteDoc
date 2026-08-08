package model

import "time"

type CheckDefinition struct {
	CheckID               CheckID
	Kind                  CheckKind
	Version               SchemaVersion
	Inputs                CheckInputs
	DependencyCheckIDs    []CheckID
	RequiredCapabilityIDs []CapabilityID
	ExecutionPolicy       ExecutionPolicy
	ExpectedCondition     ExpectedCondition
}
type ExecutionPolicy struct {
	DeadlineNS                  int64
	DependencyFailureReasonCode string
	DeadlineIsExpectedCondition bool
}
type CheckExecution struct {
	ExecutionID             ExecutionID
	CheckID                 CheckID
	BranchID                *BranchID
	VantageID               *VantageID
	StartedAt               *time.Time
	FinishedAt              *time.Time
	Lifecycle               CheckLifecycle
	Verdict                 CheckVerdict
	ReasonCode              *string
	ObservationIDs          []ObservationID
	VisibilityAssessmentIDs []VisibilityID
}
type CheckInputs struct {
	Kind            CheckInputKind
	SubjectEntityID EntityID
	VantageID       *VantageID
	AssertionID     *AssertionID
}
type ExpectedCondition struct {
	Kind            ExpectedConditionKind
	Result          string
	AddressFamily   *AddressFamily
	Port            *uint16
	Hostname        *string
	StatusMin       *uint16
	StatusMax       *uint16
	MatcherResult   *MatcherResult
	CapabilityState *CapabilityState
}
