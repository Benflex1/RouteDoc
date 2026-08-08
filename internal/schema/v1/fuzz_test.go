package v1

import (
	"os"
	"path/filepath"
	"testing"

	"routedoc/internal/model"
)

func FuzzDecode(f *testing.F) {
	root := filepath.Join("..", "..", "..", "testdata", "reports", "v1")
	paths, err := filepath.Glob(filepath.Join(root, "*", "report.json"))
	if err != nil {
		f.Fatal(err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"report_schema_version":"1.0.0"}`))
	f.Add([]byte{0xff, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		decoded, issues := Decode(data, ReadValidate)
		if len(issues) == 0 {
			if _, semantic := model.ValidatePersistedEvaluatedRun(decoded.Run); semantic != nil && len(semantic) == 0 {
				t.Fatal("impossible empty semantic issue set")
			}
		}
		decodedAgain, issuesAgain := Decode(data, ReadValidate)
		if len(issues) != len(issuesAgain) || decoded.Version != decodedAgain.Version || decoded.Exact != decodedAgain.Exact {
			t.Fatal("decoder result is not deterministic")
		}
	})
}
