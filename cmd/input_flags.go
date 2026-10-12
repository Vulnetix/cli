package cmd

// The input kinds every input-taking vdb command accepts: a vulnerability id, a
// package with ecosystem and version, a purl, a vendor and product, a CPE, a
// SWID tag, a TEI or a TEA Insights CEL expression. They mirror the API's input
// model (vdb-api .repo/inputs.md) and are sent as given; the API validates them
// and says what it read them as in the response's "resolved" block.
//
// The version flag is --package-version, not --version: the root command owns
// --version.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/pflag"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// inputFlags holds one command's input-kind flags.
type inputFlags struct {
	vulnIDs   []string
	pkg       string
	ecosystem string
	version   string
	vendor    string
	product   string
	cpe       string
	purl      string
	swid      string
	tei       string
	cel       string
}

// addInputFlags registers the input-kind flags on a command.
func addInputFlags(fs *pflag.FlagSet, f *inputFlags) {
	fs.StringSliceVar(&f.vulnIDs, "vuln-id", nil, "Vulnerability id: CVE, GHSA, CNVD, OSV, PYSEC, … (repeat or comma separate)")
	fs.StringVar(&f.pkg, "package", "", "Package name as its ecosystem writes it (npm @scope/name, Maven group:artifact)")
	fs.StringVar(&f.ecosystem, "ecosystem", "", "Ecosystem of --package: npm, pypi, maven, golang, cargo, gem, nuget, composer, deb, rpm, apk, … (aliases like pip, go, java accepted)")
	fs.StringVar(&f.version, "package-version", "", "Version of the package, product, CPE or SWID tag")
	fs.StringVar(&f.vendor, "vendor", "", "Vendor, with --product (or alone to narrow a package to that vendor)")
	fs.StringVar(&f.product, "product", "", "Product name as CVE records and CPEs name it")
	fs.StringVar(&f.cpe, "cpe", "", "CPE 2.3 formatted string or CPE 2.2 URI")
	fs.StringVar(&f.purl, "purl", "", "Package URL, e.g. pkg:npm/lodash@4.17.20")
	fs.StringVar(&f.swid, "swid", "", "SWID tag: a file path, - for stdin, or the XML itself")
	fs.StringVar(&f.tei, "tei", "", "Transparency Exchange Identifier, e.g. urn:tei:purl:vulnetix.com:pkg:npm/lodash@4.17.20")
	fs.StringVar(&f.cel, "cel", "", "TEA Insights CEL predicate over your transparency log, e.g. \"component.name.startsWith('log4j')\"")
}

// inputs builds the API inputs from the flags, reading a SWID tag from a file or
// stdin when --swid names one.
func (f *inputFlags) inputs(stdin io.Reader) (vdb.Inputs, error) {
	in := vdb.Inputs{
		Package: strings.TrimSpace(f.pkg), Ecosystem: strings.TrimSpace(f.ecosystem),
		Version: strings.TrimSpace(f.version), Vendor: strings.TrimSpace(f.vendor),
		Product: strings.TrimSpace(f.product), CPE: strings.TrimSpace(f.cpe),
		PURL: strings.TrimSpace(f.purl), TEI: strings.TrimSpace(f.tei), CEL: strings.TrimSpace(f.cel),
	}
	for _, id := range f.vulnIDs {
		if id = strings.TrimSpace(id); id != "" {
			in.VulnIDs = append(in.VulnIDs, id)
		}
	}
	if f.swid != "" {
		tag, err := readSWID(f.swid, stdin)
		if err != nil {
			return vdb.Inputs{}, err
		}
		in.SWID = tag
	}
	return in, nil
}

// readSWID returns a SWID tag given as XML, as a path to a tag file, or as -
// for stdin.
func readSWID(arg string, stdin io.Reader) (string, error) {
	s := strings.TrimSpace(arg)
	switch {
	case strings.HasPrefix(s, "<"):
		return s, nil
	case s == "-":
		b, err := io.ReadAll(io.LimitReader(stdin, 64<<10+1))
		if err != nil {
			return "", fmt.Errorf("--swid -: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	b, err := os.ReadFile(s)
	if err != nil {
		if os.IsNotExist(err) {
			// Not a file: send it as given (a base64 tag, or a tag id the API
			// will explain it cannot resolve).
			return s, nil
		}
		return "", fmt.Errorf("--swid %s: %w", s, err)
	}
	return strings.TrimSpace(string(b)), nil
}

var vulnIDLike = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,15}[-:/][A-Za-z0-9][A-Za-z0-9._:/-]{0,200}$`)

// detectInput reads one positional argument as whichever input kind it is: a
// vulnerability id, a purl, a CPE, a TEI, a SWID tag (XML, or a .swidtag/.xml
// file), or a JSON object of inputs.
func detectInput(arg string) (vdb.Inputs, error) {
	s := strings.TrimSpace(arg)
	lower := strings.ToLower(s)
	switch {
	case s == "":
		return vdb.Inputs{}, fmt.Errorf("an empty argument names nothing")
	case strings.HasPrefix(lower, "pkg:"):
		return vdb.Inputs{PURL: s}, nil
	case strings.HasPrefix(lower, "cpe:"):
		return vdb.Inputs{CPE: s}, nil
	case strings.HasPrefix(lower, "urn:tei:"), strings.HasPrefix(lower, "urn%3atei%3a"):
		return vdb.Inputs{TEI: s}, nil
	case strings.HasPrefix(s, "<"):
		return vdb.Inputs{SWID: s}, nil
	case strings.HasPrefix(s, "{"):
		var in vdb.Inputs
		if err := json.Unmarshal([]byte(s), &in); err != nil {
			return vdb.Inputs{}, fmt.Errorf("%q is not a JSON object of inputs: %w", s, err)
		}
		return in, nil
	case strings.HasSuffix(lower, ".swidtag") || strings.HasSuffix(lower, ".xml"):
		b, err := os.ReadFile(s)
		if err != nil {
			return vdb.Inputs{}, fmt.Errorf("SWID tag %s: %w", s, err)
		}
		return vdb.Inputs{SWID: strings.TrimSpace(string(b))}, nil
	case vulnIDLike.MatchString(s):
		return vdb.Inputs{VulnIDs: []string{s}}, nil
	}
	return vdb.Inputs{}, fmt.Errorf("%q is not an input this command reads: use a vulnerability id (CVE-2021-44228), a purl (pkg:npm/lodash@4.17.20), a CPE (cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*), a TEI (urn:tei:…), a SWID tag file, or the --package, --vendor/--product and --cel flags", s)
}

// mergeInputs lays b over a: list kinds are joined, a set field in b wins.
func mergeInputs(a, b vdb.Inputs) vdb.Inputs {
	out := a
	out.VulnIDs = append(append([]string{}, a.VulnIDs...), b.VulnIDs...)
	for _, f := range []struct {
		dst *string
		src string
	}{
		{&out.Package, b.Package}, {&out.Ecosystem, b.Ecosystem}, {&out.Version, b.Version},
		{&out.Vendor, b.Vendor}, {&out.Product, b.Product}, {&out.CPE, b.CPE}, {&out.PURL, b.PURL},
		{&out.SWID, b.SWID}, {&out.TEI, b.TEI}, {&out.CEL, b.CEL},
	} {
		if f.src != "" {
			*f.dst = f.src
		}
	}
	return out
}

// readInputLines reads one input per line: a JSON object of inputs (with an
// optional "key"), or anything detectInput reads. Blank lines and # comments
// are skipped.
func readInputLines(r io.Reader) ([]vdb.DefenceCountsItem, error) {
	var items []vdb.DefenceCountsItem
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 256<<10)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "{") {
			var item vdb.DefenceCountsItem
			if err := json.Unmarshal([]byte(line), &item); err != nil {
				return nil, fmt.Errorf("line %d: %w", n, err)
			}
			if item.Key == "" {
				item.Key = item.Label()
			}
			items = append(items, item)
			continue
		}
		in, err := detectInput(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		items = append(items, vdb.DefenceCountsItem{Key: line, Inputs: in})
	}
	return items, sc.Err()
}
