package bundler

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
)

// integrity check
var _ common.ParserFn = parseGemfileLockEntries

// for line in gem.splitlines():
// line = line.strip()
// line = re.sub(r"\.freeze", "", line)

// # look for the unicode \u{} format and try to convert to something python can use
// patt = re.match(r".*\.homepage *= *(.*) *", line)
// if patt:
// 	sourcepkg = json.loads(patt.group(1))

// patt = re.match(r".*\.version *= *(.*) *", line)
// if patt:
// 	v = json.loads(patt.group(1))
// 	latest = v
// 	versions.append(latest)

// patt = re.match(r".*\.licenses *= *(.*) *", line)
// if patt:
// 	lstr = re.sub(r"^\[|\]$", "", patt.group(1)).split(',')
// 	for thestr in lstr:
// 		thestr = re.sub(' *" *', "", thestr)
// 		lics.append(thestr)

// patt = re.match(r".*\.authors *= *(.*) *", line)
// if patt:
// 	lstr = re.sub(r"^\[|\]$", "", patt.group(1)).split(',')
// 	for thestr in lstr:
// 		thestr = re.sub(' *" *', "", thestr)
// 		origins.append(thestr)

// patt = re.match(r".*\.files *= *(.*) *", line)
// if patt:
// 	lstr = re.sub(r"^\[|\]$", "", patt.group(1)).split(',')
// 	for thestr in lstr:
// 		thestr = re.sub(' *" *', "", thestr)
// 		rfiles.append(thestr)

var namePattern = regexp.MustCompile(`.*\.name *= *(.*) *`)

func parseGemspecEntries(filePath string, reader io.Reader) ([]pkg.Package, error) {
	var pkgs []pkg.Package
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		// TODO: sanitize unicode? (see engine code)
		sanitizedLine := strings.TrimSpace(line)

		matches := namePattern.FindAllStringSubmatch(sanitizedLine, 1)

		pkgs = append(pkgs, pkg.Package{
			Name:     matches[0][0],
			Language: pkg.Ruby,
			Type:     pkg.BundlerPkg,
		})

	}
	return pkgs, nil
}
