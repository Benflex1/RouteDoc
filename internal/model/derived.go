package model

import "time"

type PathPosition struct {
	BranchID BranchID
	Position uint64
}
type ClaimParameters struct {
	Kind             ClaimStatementCode
	HostnameMismatch *HostnameMismatchClaimParameters
	TCPRefused       *TCPRefusedClaimParameters
	ListenerAbsent   *ListenerAbsentClaimParameters
}
type HostnameMismatchClaimParameters struct {
	PeerEntityID     EntityID
	Hostname         string
	VerificationTime time.Time
	TrustSource      TrustSource
}
type TCPRefusedClaimParameters struct {
	EndpointEntityID EntityID
	VantageID        VantageID
	ObservedAt       time.Time
}
type ListenerAbsentClaimParameters struct {
	NamespaceEntityID EntityID
	VantageID         VantageID
	Protocol          Transport
	AddressFamily     AddressFamily
	BindSemantics     BindSemantics
	Port              uint16
}
type MissingEvidenceRequirement struct {
	Kind                  MissingEvidenceKind
	ObservationKind       *ObservationKind
	VisibilitySubjectKind *VisibilitySubjectKind
	VisibilityScope       *VisibilityScope
	VantageID             *VantageID
}
type Claim struct {
	ClaimID                 ClaimID
	StatementCode           ClaimStatementCode
	Level                   ClaimLevel
	SubjectEntityIDs        []EntityID
	BranchIDs               []BranchID
	Parameters              ClaimParameters
	SupportingEvidence      []EvidenceRef
	ContradictingEvidence   []EvidenceRef
	RequiredMissingEvidence []MissingEvidenceRequirement
	RuleID                  RuleID
}
type Finding struct {
	FindingID            FindingID
	Kind                 FindingKind
	TitleCode            FindingTitleCode
	Level                ClaimLevel
	BranchIDs            []BranchID
	PathPositions        []PathPosition
	ClaimIDs             []ClaimID
	RuleID               RuleID
	Limitations          []Limitation
	SuggestedExperiments []string
	Selection            Selection
}
