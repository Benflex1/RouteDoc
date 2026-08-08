package model

import (
	"fmt"
	"strconv"
	"strings"
)

type SchemaVersion struct{ Major, Minor, Patch uint64 }

func ParseSchemaVersion(s string) (SchemaVersion, error) {
	var v SchemaVersion
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("schema version must have three components")
	}
	vals := []*uint64{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return SchemaVersion{}, fmt.Errorf("invalid schema version component %q", p)
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return SchemaVersion{}, fmt.Errorf("invalid schema version component %q", p)
			}
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return SchemaVersion{}, err
		}
		*vals[i] = n
	}
	return v, nil
}
func (v SchemaVersion) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }
func (v SchemaVersion) Exact() bool    { return v == SchemaVersion{1, 0, 0} }
