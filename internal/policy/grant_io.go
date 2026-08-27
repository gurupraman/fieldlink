package policy

import (
	"errors"
	"os"

	"github.com/gurupraman/fieldlink/internal/grant"
)

func errDenied(reason string) error {
	return errors.New(reason)
}

func parseGrantFile(path string) (*grant.Grant, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return grant.ParseYAML(data)
}

// sigPathFor returns the conventional signature file path for a grant
// document: grant.yaml -> grant.yaml.sig.
func sigPathFor(grantPath string) string {
	return grantPath + ".sig"
}
