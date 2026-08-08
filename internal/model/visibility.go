package model

import "time"

type VantageIdentity struct {
	Kind               VantageKind
	ClientNetwork      *ClientNetworkIdentity
	HostNamespace      *HostNamespaceIdentity
	ContainerNamespace *ContainerNamespaceIdentity
	UnknownNamespace   *UnknownNamespaceIdentity
}
type ClientNetworkIdentity struct{ Label string }
type HostNamespaceIdentity struct{ NamespaceInode uint64 }
type ContainerNamespaceIdentity struct{ DaemonID, ContainerID string }
type UnknownNamespaceIdentity struct{ ReasonCode string }
type VantagePoint struct {
	VantageID       VantageID
	Kind            VantageKind
	Role            VantageRole
	DisplayLabel    string
	Identity        VantageIdentity
	ParentVantageID *VantageID
	Establishment   VantageEstablishment
	Limitations     []Limitation
}
type VisibilityScope struct {
	Kind     string
	Listener *ListenerVisibilityScope
}
type ListenerVisibilityScope struct {
	NamespaceEntityID        EntityID
	Protocol                 Transport
	AddressFamily            AddressFamily
	BindSemantics            BindSemantics
	PortStart, PortEnd       uint16
	ProcessOwnershipRequired bool
}
type VisibilityAssessment struct {
	VisibilityID        VisibilityID
	SubjectKind         VisibilitySubjectKind
	VantageID           VantageID
	Scope               VisibilityScope
	Level               VisibilityLevel
	BasisObservationIDs []ObservationID
	Limitations         []Limitation
	AssessedAt          time.Time
}
