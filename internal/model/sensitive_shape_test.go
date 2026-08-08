package model

import (
	"reflect"
	"strings"
	"testing"
)

func TestSensitiveFieldAllowlist(t *testing.T) {
	bad := []string{"RawURL", "RawQuery", "Headers", "Header", "Cookie", "Credential", "Password", "Secret", "PEM", "DER", "CertificateChain", "Environment", "MatcherValue", "ConfigJSON", "RawPath"}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			for _, b := range bad {
				if strings.Contains(strings.ToLower(f.Name), strings.ToLower(b)) {
					t.Errorf("forbidden field %v.%s", typ, f.Name)
				}
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(EvidenceRun{}))
}
