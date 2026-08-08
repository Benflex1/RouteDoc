package tls

import (
	"routedoc/internal/model"
	"routedoc/internal/rules/ruleapi"
)

type hostnameMismatch struct{}

func NewHostnameMismatch() ruleapi.Rule { return hostnameMismatch{} }
func (hostnameMismatch) ID() model.RuleID {
	return model.RuleID("tls.certificate_hostname_mismatch/v1")
}
func (hostnameMismatch) Evaluate(v model.ValidatedEvidenceRun) []ruleapi.RuleCandidate {
	r := v.Value()
	out := []ruleapi.RuleCandidate{}
	for _, o := range r.Observations {
		if o.Kind != model.ObservationCertificateVerification || o.Payload.CertificateVerification == nil {
			continue
		}
		p := o.Payload.CertificateVerification
		if p.Result != model.CertHostnameMismatch || p.VerifiedHostname == "" || !p.TrustSource.Valid() || p.VerificationTime.IsZero() {
			continue
		}
		branches, positions := branchesFor(r, o.ObservationID)
		support := []ruleapi.EvidenceTemplate{{Kind: model.EvidenceKindObservation, ObservationID: o.ObservationID}}
		contra := []ruleapi.EvidenceTemplate{}
		for _, other := range r.Observations {
			if other.ObservationID == o.ObservationID || other.Kind != model.ObservationCertificateVerification || other.Payload.CertificateVerification == nil {
				continue
			}
			q := other.Payload.CertificateVerification
			if q.Result == model.CertVerified && q.PeerEntityID == p.PeerEntityID && other.VantageID != nil && o.VantageID != nil && *other.VantageID == *o.VantageID {
				contra = append(contra, ruleapi.EvidenceTemplate{Kind: model.EvidenceKindObservation, ObservationID: other.ObservationID})
			}
		}
		c := ruleapi.ClaimTemplate{LocalKey: "mismatch", StatementCode: model.StatementTLSCertificateHostnameMismatch, Level: model.ClaimLevelObserved, SubjectEntityIDs: []model.EntityID{p.PeerEntityID}, BranchIDs: branches, Parameters: model.ClaimParameters{Kind: model.StatementTLSCertificateHostnameMismatch, HostnameMismatch: &model.HostnameMismatchClaimParameters{PeerEntityID: p.PeerEntityID, Hostname: p.VerifiedHostname, VerificationTime: p.VerificationTime, TrustSource: p.TrustSource}}, SupportingEvidence: support, ContradictingEvidence: contra, RequiredMissingEvidence: []model.MissingEvidenceRequirement{}}
		f := ruleapi.FindingTemplate{Kind: model.FindingBlocker, TitleCode: model.TitleTLSCertificateHostnameMismatch, Level: model.ClaimLevelObserved, BranchIDs: append([]model.BranchID{}, branches...), PathPositions: positions, ClaimLocalKeys: []string{"mismatch"}, Limitations: []model.Limitation{}, SuggestedExperiments: []string{"inspect the certificate hostname"}, Selection: model.SelectionNone}
		out = append(out, ruleapi.RuleCandidate{CandidateKey: "tls-" + string(o.ObservationID), Claims: []ruleapi.ClaimTemplate{c}, Findings: []ruleapi.FindingTemplate{f}})
	}
	return out
}
func branchesFor(r model.EvidenceRun, id model.ObservationID) ([]model.BranchID, []model.PathPosition) {
	var b []model.BranchID
	var p []model.PathPosition
	for _, br := range r.ServicePath.Branches {
		for pos, eid := range br.OrderedEdgeIDs {
			for _, e := range r.ServicePath.Edges {
				if e.EdgeID != eid {
					continue
				}
				for _, x := range e.EvidenceRefs {
					if x.Kind == model.EvidenceKindObservation && x.ObservationID != nil && *x.ObservationID == id {
						b = append(b, br.BranchID)
						p = append(p, model.PathPosition{BranchID: br.BranchID, Position: uint64(pos)})
					}
				}
			}
		}
	}
	return b, p
}
