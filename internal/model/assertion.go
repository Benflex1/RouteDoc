package model

import "time"

type OperatorAssertion struct {
	AssertionID   AssertionID
	Kind          AssertionKind
	Parameters    AssertionParameters
	EstablishedAt time.Time
	Source        AssertionSource
}
type AssertionParameters struct {
	Kind            AssertionKind
	LocalOrigin     *LocalOriginParticipation
	ExpectedPath    *ExpectedPathEdge
	HTTP            *HTTPExpectation
	ConfigSource    *ConfigSourceSelection
	PrivateRedirect *PrivateRedirectTransitionAllowed
}
type LocalOriginParticipation struct {
	URLTargetEntityID EntityID
	HostVantageID     VantageID
}
type ExpectedPathEdge struct {
	FromEntityID EntityID
	ToEntityID   EntityID
	Relation     PathRelation
}
type HTTPExpectation struct {
	ExpectationKind ExpectationKind
	StatusMin       *uint16
	StatusMax       *uint16
	HeaderName      *string
}
type ConfigSourceSelection struct {
	ComponentKind ComponentKind
	SourceKind    ConfigSourceKind
}
type PrivateRedirectTransitionAllowed struct{ FromAddressScope, ToAddressScope string }
