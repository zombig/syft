package bundler

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseGemspec(t *testing.T) {
	var expectedPkg = pkg.Package{
		Name:     "bundler",
		Version:  "2.1.4",
		Type:     pkg.GemPkg,
		Language: pkg.Ruby,
		Metadata: pkg.GemMetadata{
			Name:    "bundler",
			Version: "2.1.4",
			Files:   []string{"exe/bundle", "exe/bundler"},
			Authors:  []string{"Andr\u00E9 Arko", "Samuel Giddins", "Colby Swandale", "Hiroshi Shibata", "David Rodr\u00EDguez", "Grey Baker", "Stephanie Morillo", "Chris Morris", "James Wen", "Tim Moore", "Andr\u00E9 Medeiros", "Jessica Lynn Suttles", "Terence Lee", "Carl Lerche", "Yehuda Katz"},
			Licenses: []string{"MIT"},
		},
	}

	fixture, err := os.Open("test-fixtures/bundler.gemspec")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parseGemSpecEntries(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse gemspec: %+v", err)
	}

	if len(actual) != 1 {
		for _, a := range actual {
			t.Log("   ", a)
		}
		t.Fatalf("unexpected package count: %d!=1", len(actual))
	}

	for _, d := range deep.Equal(actual[0], expectedPkg) {
		t.Errorf("diff: %+v", d)
	}
}