/*
Package scope provides an abstraction to allow a user to loosely define a data source to catalog and expose a common interface that
catalogers and use explore and analyze data from the data source. All valid (cataloggable) data sources are defined
within this package.
*/
package scope

import (
	"fmt"
	"strings"

	"github.com/mitchellh/go-homedir"

	"github.com/spf13/afero"

	"github.com/anchore/stereoscope"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/scope/resolvers"
)

const (
	unknownScheme   scheme = "unknown-scheme"
	directoryScheme scheme = "directory-scheme"
	imageScheme     scheme = "image-scheme"
)

type scheme string

// ImageSource represents a data source that is a container image
type ImageSource struct {
	Img *image.Image // the image object to be cataloged
}

// DirSource represents a data source that is a filesystem directory tree
type DirSource struct {
	Path string // the root path to be cataloged
}

// Scope is an object that captures the data source to be cataloged, configuration, and a specific resolver used
// in cataloging (based on the data source and configuration)
type Scope struct {
	Option   Option      // specific perspective to catalog
	Resolver Resolver    // a Resolver object to use in file path/glob resolution and file contents resolution
	ImgSrc   ImageSource // the specific image to be cataloged
	DirSrc   DirSource   // the specific directory to be cataloged
}

// NewScope produces a Scope based on userInput like dir: or image:tag
func NewScope(userInput string, o Option) (Scope, func(), error) {
	fs := afero.NewOsFs()
	parsedScheme, location, err := detectScheme(fs, image.DetectSource, userInput)
	if err != nil {
		return Scope{}, func() {}, fmt.Errorf("unable to parse input=%q: %w", userInput, err)
	}

	switch parsedScheme {
	case directoryScheme:
		fileMeta, err := fs.Stat(location)
		if err != nil {
			return Scope{}, func() {}, fmt.Errorf("unable to stat dir=%q: %w", location, err)
		}

		if !fileMeta.IsDir() {
			return Scope{}, func() {}, fmt.Errorf("given path is not a directory (path=%q): %w", location, err)
		}

		s, err := NewScopeFromDir(location)
		if err != nil {
			return Scope{}, func() {}, fmt.Errorf("could not populate scope from path=%q: %w", location, err)
		}
		return s, func() {}, nil

	case imageScheme:
		img, err := stereoscope.GetImage(location)
		cleanup := func() {
			stereoscope.Cleanup()
		}

		if err != nil || img == nil {
			return Scope{}, cleanup, fmt.Errorf("could not fetch image '%s': %w", location, err)
		}

		s, err := NewScopeFromImage(img, o)
		if err != nil {
			return Scope{}, cleanup, fmt.Errorf("could not populate scope with image: %w", err)
		}
		return s, cleanup, nil
	}

	return Scope{}, func() {}, fmt.Errorf("unable to process input for scanning: '%s'", userInput)
}

// NewScopeFromDir creates a new scope object tailored to catalog a given filesystem directory recursively.
func NewScopeFromDir(path string) (Scope, error) {
	return Scope{
		Resolver: &resolvers.DirectoryResolver{
			Path: path,
		},
		DirSrc: DirSource{
			Path: path,
		},
	}, nil
}

// NewScopeFromImage creates a new scope object tailored to catalog a given container image, relative to the
// option given (e.g. all-layers, squashed, etc)
func NewScopeFromImage(img *image.Image, option Option) (Scope, error) {
	if img == nil {
		return Scope{}, fmt.Errorf("no image given")
	}

	resolver, err := getImageResolver(img, option)
	if err != nil {
		return Scope{}, fmt.Errorf("could not determine file resolver: %w", err)
	}

	return Scope{
		Option:   option,
		Resolver: resolver,
		ImgSrc: ImageSource{
			Img: img,
		},
	}, nil
}

// Source returns the configured data source (either a dir source or container image source)
func (s Scope) Source() interface{} {
	if s.ImgSrc != (ImageSource{}) {
		return s.ImgSrc
	}
	if s.DirSrc != (DirSource{}) {
		return s.DirSrc
	}

	return nil
}

type sourceDetector func(string) (image.Source, string, error)

func detectScheme(fs afero.Fs, imageDetector sourceDetector, userInput string) (scheme, string, error) {
	if strings.HasPrefix(userInput, "dir:") {
		// blindly trust the user's scheme
		dirLocation, err := homedir.Expand(strings.TrimPrefix(userInput, "dir:"))
		if err != nil {
			return unknownScheme, "", fmt.Errorf("unable to expand directory path: %w", err)
		}
		return directoryScheme, dirLocation, nil
	}

	// we should attempt to let stereoscope determine what the source is first --just because the source is a valid directory
	// doesn't mean we yet know if it is an OCI layout directory (to be treated as an image) or if it is a generic filesystem directory.
	source, imageSpec, err := imageDetector(userInput)
	if err != nil {
		return unknownScheme, "", fmt.Errorf("unable to detect the scheme from %q: %w", userInput, err)
	}

	if source == image.UnknownSource {
		dirLocation, err := homedir.Expand(userInput)
		if err != nil {
			return unknownScheme, "", fmt.Errorf("unable to expand potential directory path: %w", err)
		}

		fileMeta, err := fs.Stat(dirLocation)
		if err != nil {
			return unknownScheme, "", nil
		}

		if fileMeta.IsDir() {
			return directoryScheme, dirLocation, nil
		}
		return unknownScheme, "", nil
	}

	return imageScheme, imageSpec, nil
}
