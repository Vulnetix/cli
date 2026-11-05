package analyze

// Exposure of a declared infrastructure resource: is it reachable from the internet?
//
// The collector emits Properties["exposure"] on the iac_resource nodes whose type can be
// reached at all (load balancers, security groups, function URLs, public IPs, databases,
// Kubernetes Services and Ingresses), as one of:
//
//	public    the declaration says the world can reach it
//	internal  the declaration says it cannot (internal = true, only private CIDRs,
//	          AWS_IAM auth, ClusterIP)
//	unknown   it could be either and the file does not say (a variable, a reference, a
//	          partner CIDR, an attribute left to a default we do not model)
//
// Unknown is not internal. A value that is a variable or a reference is never read as
// either answer, and a resource type that is not a network-facing one carries no exposure
// at all, so the server never mistakes "not evaluated" for "internal". The server raises
// "declared public and not deployed" from `public` only.

import (
	"net/netip"
	"regexp"
	"strings"
)

const (
	exposurePublic   = "public"
	exposureInternal = "internal"
	exposureUnknown  = "unknown"
)

var (
	cidrLiteral = regexp.MustCompile(`"([0-9A-Fa-f:.]+/[0-9]{1,3})"`)
	hclQuoted   = regexp.MustCompile(`^"([^"]*)"$`)
)

// ---- HCL (Terraform) ---------------------------------------------------------------------

// hclBlock is the top level of a Terraform block body: its attributes and nested blocks.
type hclBlock struct {
	attrs  map[string]string
	blocks map[string][]string
}

// stripHCLComments removes # // and /* */ comments outside string literals, keeping
// newlines.
func stripHCLComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			j := skipString(s, i)
			b.WriteString(s[i : j+1])
			i = j
		case c == '#' || (c == '/' && i+1 < len(s) && s[i+1] == '/'):
			for i < len(s) && s[i] != '\n' {
				i++
			}
			if i < len(s) {
				b.WriteByte('\n')
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			b.WriteString(strings.Repeat("\n", strings.Count(s[i:i+2+end+2], "\n")))
			i += 2 + end + 1
		default:
			b.WriteByte(c)
		}
	}

	return b.String()
}

// parseHCLBlock reads the top level of a block body. Nested blocks are returned raw, by
// name; a `dynamic "x" { content { ... } }` is returned as the block `x`.
func parseHCLBlock(body string) hclBlock {
	out := hclBlock{attrs: map[string]string{}, blocks: map[string][]string{}}
	i := 0
	for i < len(body) {
		for i < len(body) && strings.ContainsRune(" \t\r\n,", rune(body[i])) {
			i++
		}
		start := i
		for i < len(body) && (isIdentByte(body[i]) || body[i] == '-') {
			i++
		}
		if i == start {
			i++

			continue
		}
		name := body[start:i]
		for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
			i++
		}
		switch {
		case i < len(body) && body[i] == '=' && (i+1 >= len(body) || body[i+1] != '='):
			i++
			vs := i
			depth := 0
			for i < len(body) {
				c := body[i]
				if c == '"' {
					i = skipString(body, i) + 1

					continue
				}
				if c == '(' || c == '[' || c == '{' {
					depth++
				}
				if c == ')' || c == ']' || c == '}' {
					depth--
				}
				if c == '\n' && depth <= 0 {
					break
				}
				i++
			}
			out.attrs[name] = strings.TrimSpace(body[vs:i])
		default:
			// A block: optional string labels, then '{'.
			label := ""
			for i < len(body) && body[i] == '"' {
				j := skipString(body, i)
				if j <= i { // a quote that ends its line opens no label
					i = j + 1
					break
				}
				label = body[i+1 : j]
				i = j + 1
				for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
					i++
				}
			}
			if i >= len(body) || body[i] != '{' {
				continue
			}
			end := matchBracket(body, i)
			if end < 0 {
				return out
			}
			inner := body[i+1 : end]
			if name == "dynamic" && label != "" {
				name = label
				if cb := parseHCLBlock(inner).blocks["content"]; len(cb) > 0 {
					inner = cb[0]
				}
			}
			out.blocks[name] = append(out.blocks[name], inner)
			i = end + 1
		}
	}

	return out
}

func hclString(v string) (string, bool) {
	m := hclQuoted.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return "", false
	}

	return m[1], true
}

func hclBool(v string) (bool, bool) {
	switch strings.TrimSpace(v) {
	case "true", `"true"`:
		return true, true
	case "false", `"false"`:
		return false, true
	}

	return false, false
}

// terraformExposure classifies a Terraform resource from its body. ok is false for a
// resource type that is not network-facing.
func terraformExposure(resourceType, body string) (exposure string, ok bool) {
	b := parseHCLBlock(stripHCLComments(body))

	switch resourceType {
	case "aws_lb", "aws_alb", "aws_elb":
		v, set := b.attrs["internal"]
		if !set {
			return exposurePublic, true // the provider default is an internet-facing balancer
		}
		if internal, isBool := hclBool(v); isBool {
			return pick(internal, exposureInternal, exposurePublic), true
		}

		return exposureUnknown, true

	case "aws_lambda_function_url":
		v, set := b.attrs["authorization_type"]
		if s, isStr := hclString(v); set && isStr {
			switch strings.ToUpper(s) {
			case "NONE":
				return exposurePublic, true
			case "AWS_IAM":
				return exposureInternal, true
			}
		}

		return exposureUnknown, true

	case "aws_eip_association":
		return exposurePublic, true

	case "aws_eip":
		for _, k := range []string{"instance", "network_interface"} {
			if _, set := b.attrs[k]; set {
				return exposurePublic, true
			}
		}

		return exposureUnknown, true

	case "aws_instance", "aws_spot_instance_request", "aws_launch_configuration", "aws_network_interface":
		return publicIPExposure(b, "network_interface"), true

	case "aws_launch_template":
		return publicIPExposure(b, "network_interfaces"), true

	case "aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster", "aws_dms_replication_instance":
		if v, set := b.attrs["publicly_accessible"]; set {
			if pub, isBool := hclBool(v); isBool {
				return pick(pub, exposurePublic, exposureInternal), true
			}
		}

		return exposureUnknown, true

	case "aws_security_group":
		var cidrs []string
		for _, in := range b.blocks["ingress"] {
			cidrs = append(cidrs, literalCIDRs(in)...)
		}
		if v, set := b.attrs["ingress"]; set { // ingress = [ { cidr_blocks = [...] } ]
			cidrs = append(cidrs, literalCIDRs(v)...)
		}

		return cidrExposure(cidrs), true

	case "aws_security_group_rule":
		if v, set := b.attrs["type"]; set {
			if s, isStr := hclString(v); isStr && s != "ingress" {
				return "", false // an egress rule opens nothing inwards
			}
		}

		return cidrExposure(literalCIDRs(b.attrs["cidr_blocks"] + " " + b.attrs["ipv6_cidr_blocks"])), true

	case "aws_vpc_security_group_ingress_rule":
		return cidrExposure(literalCIDRs(b.attrs["cidr_ipv4"] + " " + b.attrs["cidr_ipv6"])), true
	}

	return "", false
}

// publicIPExposure reads associate_public_ip_address from a block's own attributes or from
// the nested network interface blocks.
func publicIPExposure(b hclBlock, nested string) string {
	seen := []string{b.attrs["associate_public_ip_address"]}
	for _, n := range b.blocks[nested] {
		seen = append(seen, parseHCLBlock(n).attrs["associate_public_ip_address"])
	}
	result := exposureUnknown
	for _, v := range seen {
		if v == "" {
			continue
		}
		pub, isBool := hclBool(v)
		switch {
		case !isBool:
			continue
		case pub:
			return exposurePublic
		default:
			result = exposureInternal
		}
	}

	return result
}

func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}

	return no
}

func literalCIDRs(s string) []string {
	var out []string
	for _, m := range cidrLiteral.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}

	return out
}

// cidrExposure classifies a set of ingress source ranges: any world range is public; all
// private ranges is internal; anything else (none found, a partner range) is unknown.
func cidrExposure(cidrs []string) string {
	if len(cidrs) == 0 {
		return exposureUnknown
	}
	allPrivate := true
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			allPrivate = false

			continue
		}
		if p.Bits() == 0 {
			return exposurePublic
		}
		if !isPrivatePrefix(p) {
			allPrivate = false
		}
	}
	if allPrivate {
		return exposureInternal
	}

	return exposureUnknown
}

// isPrivatePrefix is RFC 1918, carrier-grade NAT, loopback, link-local and the IPv6
// unique-local range.
func isPrivatePrefix(p netip.Prefix) bool {
	a := p.Addr()

	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// ---- CloudFormation -----------------------------------------------------------------------

// cloudFormationExposure classifies a CloudFormation or SAM resource.
func cloudFormationExposure(typ string, res map[string]any) (exposure string, ok bool) {
	props, _ := mapAny(res["Properties"])
	switch typ {
	case "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancing::LoadBalancer":
		switch strings.ToLower(anyString(props["Scheme"])) {
		case "":
			if props["Scheme"] != nil {
				return exposureUnknown, true // an intrinsic function
			}

			return exposurePublic, true // the default scheme is internet-facing
		case "internet-facing":
			return exposurePublic, true
		case "internal":
			return exposureInternal, true
		}

		return exposureUnknown, true

	case "AWS::Lambda::Url":
		return authTypeExposure(props["AuthType"]), true

	case "AWS::Serverless::Function":
		cfg, has := mapAny(props["FunctionUrlConfig"])
		if !has {
			return "", false
		}

		return authTypeExposure(cfg["AuthType"]), true

	case "AWS::EC2::EIPAssociation":
		return exposurePublic, true

	case "AWS::EC2::EIP":
		if props["InstanceId"] != nil || props["NetworkInterfaceId"] != nil {
			return exposurePublic, true
		}

		return exposureUnknown, true

	case "AWS::EC2::SecurityGroup":
		var cidrs []string
		for _, rule := range anySlice(props["SecurityGroupIngress"]) {
			if r, isMap := mapAny(rule); isMap {
				cidrs = append(cidrs, anyString(r["CidrIp"]), anyString(r["CidrIpv6"]))
			}
		}

		return cidrExposure(nonEmptyCIDRs(cidrs)), true

	case "AWS::EC2::SecurityGroupIngress":
		return cidrExposure(nonEmptyCIDRs([]string{anyString(props["CidrIp"]), anyString(props["CidrIpv6"])})), true

	case "AWS::EC2::Instance", "AWS::EC2::NetworkInterface":
		return cfnPublicIP(props["NetworkInterfaces"], props["AssociatePublicIpAddress"]), true

	case "AWS::EC2::LaunchTemplate":
		data, _ := mapAny(props["LaunchTemplateData"])

		return cfnPublicIP(data["NetworkInterfaces"], nil), true

	case "AWS::RDS::DBInstance", "AWS::Redshift::Cluster":
		if pub, isBool := anyBool(props["PubliclyAccessible"]); isBool {
			return pick(pub, exposurePublic, exposureInternal), true
		}

		return exposureUnknown, true
	}

	return "", false
}

func authTypeExposure(v any) string {
	switch strings.ToUpper(anyString(v)) {
	case "NONE":
		return exposurePublic
	case "AWS_IAM":
		return exposureInternal
	}

	return exposureUnknown
}

func cfnPublicIP(interfaces any, direct any) string {
	values := []any{direct}
	for _, ni := range anySlice(interfaces) {
		if m, isMap := mapAny(ni); isMap {
			values = append(values, m["AssociatePublicIpAddress"])
		}
	}
	result := exposureUnknown
	for _, v := range values {
		pub, isBool := anyBool(v)
		switch {
		case !isBool:
			continue
		case pub:
			return exposurePublic
		default:
			result = exposureInternal
		}
	}

	return result
}

func nonEmptyCIDRs(in []string) []string {
	var out []string
	for _, c := range in {
		if c != "" {
			out = append(out, c)
		}
	}

	return out
}

func anyString(v any) string {
	s, _ := v.(string)

	return strings.TrimSpace(s)
}

func anyBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		return hclBool(strings.ToLower(x))
	}

	return false, false
}

func anySlice(v any) []any {
	s, _ := v.([]any)

	return s
}

// ---- Kubernetes ---------------------------------------------------------------------------

// internalLBAnnotations name a cloud load balancer that is not internet-facing.
var internalLBAnnotations = map[string][]string{
	"service.beta.kubernetes.io/aws-load-balancer-internal":               {"true"},
	"service.beta.kubernetes.io/aws-load-balancer-scheme":                 {"internal"},
	"service.beta.kubernetes.io/azure-load-balancer-internal":             {"true"},
	"service.beta.kubernetes.io/oci-load-balancer-internal":               {"true"},
	"cloud.google.com/load-balancer-type":                                 {"internal"},
	"networking.gke.io/load-balancer-type":                                {"internal"},
	"alb.ingress.kubernetes.io/scheme":                                    {"internal"},
	"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type-scheme": {"internal"},
}

// kubernetesExposure classifies a Service or Ingress manifest.
func kubernetesExposure(kind string, doc map[string]any) (exposure string, ok bool) {
	meta, _ := mapAny(doc["metadata"])
	annotations, _ := mapAny(meta["annotations"])
	spec, _ := mapAny(doc["spec"])

	internalAnnotated := false
	for k, wants := range internalLBAnnotations {
		got := strings.ToLower(anyString(annotations[k]))
		if got == "" {
			continue
		}
		for _, w := range wants {
			if got == w {
				internalAnnotated = true
			}
		}
	}

	switch kind {
	case "Service":
		switch anyString(spec["type"]) {
		case "LoadBalancer":
			return pick(internalAnnotated, exposureInternal, exposurePublic), true
		case "NodePort":
			return exposurePublic, true
		case "", "ClusterIP":
			return exposureInternal, true
		}

		return exposureUnknown, true

	case "Ingress":
		class := strings.ToLower(anyString(spec["ingressClassName"]) + " " + anyString(annotations["kubernetes.io/ingress.class"]))
		if internalAnnotated || strings.Contains(class, "internal") {
			return exposureInternal, true
		}

		return exposurePublic, true
	}

	return "", false
}

// terraformBodyAfter returns the text between the braces of the block whose header ends at
// off (the closing quote of the resource name), or "" when the braces do not balance.
func terraformBodyAfter(src string, off int) string {
	i := off
	for i < len(src) && (src[i] == ' ' || src[i] == '\t' || src[i] == '\r' || src[i] == '\n') {
		i++
	}
	if i >= len(src) || src[i] != '{' {
		return ""
	}
	end := matchBracket(src, i)
	if end < 0 {
		return ""
	}

	return src[i+1 : end]
}
