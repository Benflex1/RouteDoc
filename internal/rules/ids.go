package rules

import "fmt"

func claimID(n int) string   { return fmt.Sprintf("claim-%06d", n) }
func findingID(n int) string { return fmt.Sprintf("finding-%06d", n) }
