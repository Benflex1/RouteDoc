package main

func parseRenderArgs(a []string) (string, bool, bool, bool) {
	path := ""
	verbose, jsonOut := false, false
	for _, x := range a {
		switch x {
		case "--verbose":
			if verbose {
				return "", false, false, false
			}
			verbose = true
		case "--json":
			if jsonOut {
				return "", false, false, false
			}
			jsonOut = true
		default:
			if path != "" {
				return "", false, false, false
			}
			path = x
		}
	}
	return path, verbose, jsonOut, path != ""
}
func parseExplainArgs(a []string) (string, string, bool, bool) {
	pos := []string{}
	jsonOut := false
	for _, x := range a {
		if x == "--json" {
			if jsonOut {
				return "", "", false, false
			}
			jsonOut = true
		} else {
			pos = append(pos, x)
		}
	}
	if len(pos) != 2 {
		return "", "", false, false
	}
	return pos[0], pos[1], jsonOut, true
}
func parseValidateArgs(a []string) (string, bool, bool) {
	path := ""
	jsonOut := false
	for _, x := range a {
		if x == "--json" {
			if jsonOut {
				return "", false, false
			}
			jsonOut = true
		} else {
			if path != "" {
				return "", false, false
			}
			path = x
		}
	}
	return path, jsonOut, path != ""
}
