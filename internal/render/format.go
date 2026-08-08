package render

import (
	"fmt"
	"io"
	"strings"

	"routedoc/internal/model"
)

func targetText(t model.Target) string {
	return fmt.Sprintf("%s://%s:%d (PathSummary present=%t root=%t segments=%d trailing_slash=%t query_present=%t)", t.Scheme, t.Hostname, t.EffectivePort, t.Path.Present, t.Path.IsRoot, t.Path.SegmentCount, t.Path.TrailingSlash, t.Path.QueryPresent)
}
func titleText(t model.FindingTitleCode) string {
	switch t {
	case model.TitleTLSCertificateHostnameMismatch:
		return "TLS certificate hostname mismatch"
	case model.TitleTCPConnectionRefused:
		return "TCP connection refused from this vantage"
	case model.TitleNoMatchingListenerVisible:
		return "No matching listener visible"
	}
	return string(t)
}
func writeLine(w io.Writer, s string) error { _, err := io.WriteString(w, s+"\n"); return err }
func branchText(b model.Branch) string {
	return fmt.Sprintf("%s goal=%s edges=%d", b.BranchID, b.Goal, len(b.OrderedEdgeIDs))
}
func refsText(v []model.EvidenceRef) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = string(x.Kind) + ":" + refID(x)
	}
	return strings.Join(parts, ", ")
}
func refID(x model.EvidenceRef) string {
	if x.ObservationID != nil {
		return string(*x.ObservationID)
	}
	if x.ClaimID != nil {
		return string(*x.ClaimID)
	}
	if x.VisibilityID != nil {
		return string(*x.VisibilityID)
	}
	if x.AssertionID != nil {
		return string(*x.AssertionID)
	}
	return ""
}
