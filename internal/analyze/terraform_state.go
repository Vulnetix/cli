package analyze

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maxTerraformIdentityFileBytes = 32 << 20

var (
	awsARNRe              = regexp.MustCompile(`^arn:(aws[a-zA-Z-]*):([^:]+):([^:]*):([^:]*):(.+)$`)
	awsResourceIDRe       = regexp.MustCompile(`^(?:ami|i|vol|snap|vpc|subnet|sg|eni|eipalloc|eipassoc|igw|nat|rtb|acl|vpce|vpce-svc|pcx|tgw|tgw-attach|tgw-rtb|fs|fsap|lt)-[0-9a-fA-F]{6,}$`)
	azureIDRe             = regexp.MustCompile(`(?i)^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/([^/]+)/(.+)$`)
	gcpSelfLinkProjectRe  = regexp.MustCompile(`(?i)(?:^|/)projects/([^/]+)(?:/|$)`)
	gcpSelfLinkLocationRe = regexp.MustCompile(`(?i)/(?:regions|zones|locations)/([^/]+)(?:/|$)`)
	awsAccessKeyIDRe      = regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b`)
)

type terraformIdentityIndex struct {
	byAddress map[string]terraformResourceIdentity
	outputs   []terraformOutputIdentity
}

type terraformResourceIdentity struct {
	Address     string
	Type        string
	Name        string
	Provider    string
	SourcePath  string
	Primary     string
	Identifiers map[string]string
	Metadata    map[string]string
}

type terraformOutputIdentity struct {
	Name        string
	SourcePath  string
	Primary     string
	Identifiers map[string]string
	Metadata    map[string]string
}

func collectTerraformIdentities(root string) *terraformIdentityIndex {
	idx := &terraformIdentityIndex{byAddress: map[string]terraformResourceIdentity{}}

	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}

			return nil
		}
		if !looksTerraformIdentityFile(d.Name()) {
			return nil
		}
		if info, statErr := d.Info(); statErr != nil || info.Size() > maxTerraformIdentityFileBytes {
			return nil
		}

		body, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}
		var doc map[string]any
		if json.Unmarshal(body, &doc) != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)

		idx.addTerraformStateDoc(rel, doc)

		return nil
	})

	return idx
}

func looksTerraformIdentityFile(name string) bool {
	lower := strings.ToLower(name)
	if lower == "terraform.tfstate" || lower == "terraform.tfstate.backup" ||
		strings.HasSuffix(lower, ".tfstate") || strings.HasSuffix(lower, ".tfstate.backup") ||
		strings.HasSuffix(lower, ".tfstate.json") {

		return true
	}
	if !strings.HasSuffix(lower, ".json") {
		return false
	}

	return strings.Contains(lower, "output") || strings.Contains(lower, "tfstate") || strings.Contains(lower, "terraform")
}

func (idx *terraformIdentityIndex) addTerraformStateDoc(rel string, doc map[string]any) {
	if outputs, ok := mapAny(doc["outputs"]); ok {
		idx.addTerraformOutputs(rel, outputs)
	} else if terraformOutputMap(doc) {
		idx.addTerraformOutputs(rel, doc)
	}

	if resources, ok := doc["resources"].([]any); ok {
		idx.addLegacyTerraformResources(rel, resources)
	}

	if values, ok := mapAny(doc["values"]); ok {
		if outputs, ok := mapAny(values["outputs"]); ok {
			idx.addTerraformOutputs(rel, outputs)
		}
		if rootModule, ok := mapAny(values["root_module"]); ok {
			idx.addTerraformModule(rel, "", rootModule)
		}
	}

	if planned, ok := mapAny(doc["planned_values"]); ok {
		if rootModule, ok := mapAny(planned["root_module"]); ok {
			idx.addTerraformModule(rel, "", rootModule)
		}
	}
}

func terraformOutputMap(doc map[string]any) bool {
	if len(doc) == 0 {
		return false
	}
	for _, raw := range doc {
		output, ok := mapAny(raw)
		if !ok {
			return false
		}
		if _, hasValue := output["value"]; !hasValue {
			return false
		}
	}

	return true
}

func (idx *terraformIdentityIndex) addLegacyTerraformResources(rel string, resources []any) {
	for _, raw := range resources {
		res, ok := mapAny(raw)
		if !ok || strings.TrimSpace(stringValue(res["mode"])) == "data" {
			continue
		}
		typ := strings.TrimSpace(stringValue(res["type"]))
		name := strings.TrimSpace(stringValue(res["name"]))
		if typ == "" || name == "" {
			continue
		}
		moduleAddr := strings.TrimSpace(stringValue(res["module"]))
		address := typ + "." + name
		if moduleAddr != "" {
			address = moduleAddr + "." + address
		}
		provider := strings.TrimSpace(stringValue(res["provider"]))
		for _, rawInst := range sliceAny(res["instances"]) {
			inst, ok := mapAny(rawInst)
			if !ok {
				continue
			}
			values, ok := mapAny(inst["attributes"])
			if !ok {
				continue
			}
			idx.addResourceIdentity(rel, address, typ, name, provider, values, sensitiveKeys(inst))
		}
	}
}

func (idx *terraformIdentityIndex) addTerraformModule(rel, inheritedModule string, module map[string]any) {
	moduleAddr := strings.TrimSpace(stringValue(module["address"]))
	if moduleAddr == "" {
		moduleAddr = inheritedModule
	}
	for _, raw := range sliceAny(module["resources"]) {
		res, ok := mapAny(raw)
		if !ok || strings.TrimSpace(stringValue(res["mode"])) == "data" {
			continue
		}
		address := strings.TrimSpace(stringValue(res["address"]))
		typ := strings.TrimSpace(stringValue(res["type"]))
		name := strings.TrimSpace(stringValue(res["name"]))
		if address == "" && typ != "" && name != "" {
			address = typ + "." + name
			if moduleAddr != "" {
				address = moduleAddr + "." + address
			}
		}
		if address == "" || typ == "" || name == "" {
			continue
		}
		values, ok := mapAny(res["values"])
		if !ok {
			continue
		}
		idx.addResourceIdentity(rel, address, typ, name, strings.TrimSpace(stringValue(res["provider_name"])), values, sensitiveKeys(res))
	}
	for _, raw := range sliceAny(module["child_modules"]) {
		child, ok := mapAny(raw)
		if ok {
			idx.addTerraformModule(rel, moduleAddr, child)
		}
	}
}

func (idx *terraformIdentityIndex) addResourceIdentity(rel, address, typ, name, provider string, values map[string]any, sensitive map[string]bool) {
	ids, meta := extractCloudIdentifiers(typ, provider, values, sensitive)
	primary := primaryCloudIdentifier(ids)
	if primary == "" && len(ids) == 0 {
		return
	}
	identity := terraformResourceIdentity{
		Address:     address,
		Type:        typ,
		Name:        name,
		Provider:    provider,
		SourcePath:  rel,
		Primary:     primary,
		Identifiers: ids,
		Metadata:    meta,
	}
	idx.byAddress[address] = mergeResourceIdentity(idx.byAddress[address], identity)
}

func (idx *terraformIdentityIndex) addTerraformOutputs(rel string, outputs map[string]any) {
	names := make([]string, 0, len(outputs))
	for name := range outputs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := outputs[name]
		output, ok := mapAny(raw)
		if !ok || boolValue(output["sensitive"]) {
			continue
		}
		values := outputIdentifierValues(output["value"])
		if len(values) == 0 {
			continue
		}
		ids, meta := classifyIdentifierValues(values)
		primary := primaryCloudIdentifier(ids)
		if primary == "" {
			continue
		}
		idx.outputs = append(idx.outputs, terraformOutputIdentity{
			Name:        name,
			SourcePath:  rel,
			Primary:     primary,
			Identifiers: ids,
			Metadata:    meta,
		})
	}
}

func (idx *terraformIdentityIndex) lookup(address string) (terraformResourceIdentity, bool) {
	if idx == nil {
		return terraformResourceIdentity{}, false
	}
	identity, ok := idx.byAddress[address]

	return identity, ok
}

func (idx *terraformIdentityIndex) stateOnlyResources(declared map[string]bool) []terraformResourceIdentity {
	if idx == nil {
		return nil
	}
	out := make([]terraformResourceIdentity, 0, len(idx.byAddress))
	for address, identity := range idx.byAddress {
		if declared[address] {
			continue
		}
		out = append(out, identity)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })

	return out
}

func (idx *terraformIdentityIndex) outputOnlyIdentifiers(knownPrimary map[string]bool) []terraformOutputIdentity {
	if idx == nil {
		return nil
	}
	byPrimary := map[string]terraformOutputIdentity{}
	for _, output := range idx.outputs {
		if output.Primary == "" || knownPrimary[output.Primary] {
			continue
		}
		if existing, ok := byPrimary[output.Primary]; !ok || preferTerraformOutput(output, existing) {
			byPrimary[output.Primary] = output
		}
	}
	out := make([]terraformOutputIdentity, 0, len(byPrimary))
	for _, output := range byPrimary {
		out = append(out, output)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourcePath != out[j].SourcePath {
			return out[i].SourcePath < out[j].SourcePath
		}

		return out[i].Name < out[j].Name
	})

	return out
}

func preferTerraformOutput(next, current terraformOutputIdentity) bool {
	if nextScore, currentScore := terraformOutputIdentifierScore(next.Name), terraformOutputIdentifierScore(current.Name); nextScore != currentScore {
		return nextScore > currentScore
	}
	if next.SourcePath != current.SourcePath {
		return next.SourcePath < current.SourcePath
	}

	return next.Name < current.Name
}

func terraformOutputIdentifierScore(name string) int {
	name = strings.ToLower(strings.ReplaceAll(name, "-", "_"))
	switch {
	case strings.Contains(name, "arn") || strings.Contains(name, "resource_id") || strings.Contains(name, "resource_uri") || strings.Contains(name, "self_link"):
		return 3
	case strings.HasSuffix(name, "_id") || strings.Contains(name, "identifier"):
		return 2
	default:
		return 1
	}
}

func mergeResourceIdentity(old, next terraformResourceIdentity) terraformResourceIdentity {
	if old.Address == "" {
		return next
	}
	if old.Identifiers == nil {
		old.Identifiers = map[string]string{}
	}
	for k, v := range next.Identifiers {
		if old.Identifiers[k] == "" {
			old.Identifiers[k] = v
		}
	}
	if old.Metadata == nil {
		old.Metadata = map[string]string{}
	}
	for k, v := range next.Metadata {
		if old.Metadata[k] == "" {
			old.Metadata[k] = v
		}
	}
	if old.Primary == "" {
		old.Primary = next.Primary
	}
	if old.SourcePath == "" {
		old.SourcePath = next.SourcePath
	}
	if old.Provider == "" {
		old.Provider = next.Provider
	}

	return old
}

func extractCloudIdentifiers(resourceType, provider string, values map[string]any, sensitive map[string]bool) (map[string]string, map[string]string) {
	candidates := map[string]string{}
	providerHint := terraformProviderHint(resourceType, provider)
	for key, raw := range values {
		key = strings.TrimSpace(key)
		if key == "" || sensitive[key] || sensitiveFieldName(key) {
			continue
		}
		value := strings.TrimSpace(stringValue(raw))
		if value == "" || sensitiveIdentifierValue(resourceType, key, value) {
			continue
		}
		if isCloudIdentifierValue(value) || providerHint != "" && isAllowedIdentifierField(key) {
			candidates[key] = value
		}
	}

	return classifyNamedIdentifierValues(candidates, resourceType, provider)
}

func classifyNamedIdentifierValues(values map[string]string, resourceType, provider string) (map[string]string, map[string]string) {
	ids := map[string]string{}
	meta := map[string]string{}

	for key, value := range values {
		addClassifiedIdentifier(ids, meta, key, value)
	}
	if providerHint := terraformProviderHint(resourceType, provider); providerHint != "" && meta["cloudProvider"] == "" {
		meta["cloudProvider"] = providerHint
	}

	return ids, meta
}

func classifyIdentifierValues(values []string) (map[string]string, map[string]string) {
	ids := map[string]string{}
	meta := map[string]string{}
	for _, value := range values {
		addClassifiedIdentifier(ids, meta, "value", value)
	}

	return ids, meta
}

func addClassifiedIdentifier(ids, meta map[string]string, key, value string) {
	lowerKey := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	switch {
	case isAWSARN(value):
		setIdentifier(ids, "awsArn", value)
		if m := awsARNRe.FindStringSubmatch(value); len(m) == 6 {
			meta["cloudProvider"] = "aws"
			meta["awsPartition"] = m[1]
			meta["awsService"] = m[2]
			if m[3] != "" {
				meta["awsRegion"] = m[3]
			}
			if m[4] != "" {
				meta["awsAccountId"] = m[4]
			}
			meta["awsResource"] = m[5]
		}
	case strings.HasPrefix(strings.ToLower(value), "/subscriptions/"):
		setIdentifier(ids, "azureResourceId", value)
		if m := azureIDRe.FindStringSubmatch(value); len(m) == 5 {
			meta["cloudProvider"] = "azure"
			meta["azureSubscriptionId"] = m[1]
			meta["azureResourceGroup"] = m[2]
			meta["azureResourceProvider"] = m[3]
			meta["azureResourcePath"] = m[4]
		}
	case isGCPSelfLink(value):
		setIdentifier(ids, "gcpSelfLink", value)
		meta["cloudProvider"] = "gcp"
		if m := gcpSelfLinkProjectRe.FindStringSubmatch(value); len(m) == 2 {
			meta["gcpProject"] = m[1]
		}
		if m := gcpSelfLinkLocationRe.FindStringSubmatch(value); len(m) == 2 {
			meta["gcpLocation"] = m[1]
		}
	case isAWSResourceID(value):
		setIdentifier(ids, "id", value)
		meta["cloudProvider"] = "aws"
	case lowerKey == "id":
		setIdentifier(ids, "id", value)
	case lowerKey == "self_link" || lowerKey == "self_link_unique":
		setIdentifier(ids, "selfLink", value)
	case strings.HasSuffix(lowerKey, "arn"):
		setIdentifier(ids, lowerKey, value)
	case lowerKey == "resource_id" || lowerKey == "resource_uri":
		setIdentifier(ids, lowerKey, value)
	case lowerKey == "project" || lowerKey == "project_id":
		meta["gcpProject"] = value
	case lowerKey == "region" || lowerKey == "zone" || lowerKey == "location":
		meta["cloudLocation"] = value
	case lowerKey == "account_id":
		meta["awsAccountId"] = value
	case lowerKey == "subscription_id":
		meta["azureSubscriptionId"] = value
	case lowerKey == "resource_group_name":
		meta["azureResourceGroup"] = value
	}
}

func setIdentifier(ids map[string]string, key, value string) {
	if value == "" || ids[key] != "" {
		return
	}
	ids[key] = value
}

func primaryCloudIdentifier(ids map[string]string) string {
	for _, key := range []string{
		"awsArn",
		"azureResourceId",
		"gcpSelfLink",
		"resource_id",
		"resource_uri",
		"id",
		"selfLink",
	} {
		if value := ids[key]; value != "" {
			return value
		}
	}
	keys := make([]string, 0, len(ids))
	for key := range ids {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}

	return ids[keys[0]]
}

func isAllowedIdentifierField(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	switch key {
	case "arn", "id", "self_link", "self_link_unique", "resource_id", "resource_uri",
		"project", "project_id", "region", "zone", "location", "account_id",
		"subscription_id", "resource_group_name":

		return true
	}

	return strings.HasSuffix(key, "_arn") || strings.HasSuffix(key, "_id")
}

func isCloudIdentifierValue(value string) bool {
	return isAWSARN(value) ||
		strings.HasPrefix(strings.ToLower(value), "/subscriptions/") ||
		isGCPSelfLink(value) ||
		isAWSResourceID(value)
}

func isAWSARN(value string) bool {
	return awsARNRe.MatchString(value)
}

func isAWSResourceID(value string) bool {
	return awsResourceIDRe.MatchString(value)
}

func isGCPSelfLink(value string) bool {
	lower := strings.ToLower(value)

	return strings.Contains(lower, "googleapis.com/") && strings.Contains(lower, "/projects/") ||
		strings.HasPrefix(lower, "//") && strings.Contains(lower, ".googleapis.com/projects/") ||
		strings.HasPrefix(lower, "projects/")
}

func terraformProviderHint(resourceType, provider string) string {
	lower := strings.ToLower(resourceType + " " + provider)
	switch {
	case strings.HasPrefix(strings.ToLower(resourceType), "aws_") || strings.Contains(lower, "hashicorp/aws"):
		return "aws"
	case strings.HasPrefix(strings.ToLower(resourceType), "azurerm_") || strings.Contains(lower, "hashicorp/azurerm"):
		return "azure"
	case strings.HasPrefix(strings.ToLower(resourceType), "google_") || strings.Contains(lower, "hashicorp/google"):
		return "gcp"
	}

	return ""
}

func sensitiveKeys(obj map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, key := range []string{"sensitive_values", "attributes_sensitive"} {
		if raw, ok := obj[key]; ok {
			collectSensitiveKeys("", raw, out)
		}
	}
	if raw, ok := obj["sensitive_attributes"]; ok {
		for _, path := range sliceAny(raw) {
			if text := strings.TrimSpace(stringValue(path)); text != "" {
				if head := strings.Split(strings.Trim(text, "."), ".")[0]; head != "" {
					out[head] = true
				}
			}
		}
	}

	return out
}

func collectSensitiveKeys(prefix string, raw any, out map[string]bool) {
	switch value := raw.(type) {
	case bool:
		if value && prefix != "" {
			out[strings.Split(prefix, ".")[0]] = true
		}
	case map[string]any:
		for key, child := range value {
			next := key
			if prefix != "" {
				next = prefix + "." + key
			}
			collectSensitiveKeys(next, child, out)
		}
	case []any:
		for _, child := range value {
			collectSensitiveKeys(prefix, child, out)
		}
	}
}

func sensitiveFieldName(key string) bool {
	key = strings.ToLower(key)
	for _, word := range []string{"password", "passwd", "secret", "token", "private_key", "client_secret", "access_key"} {
		if strings.Contains(key, word) {
			return true
		}
	}

	return false
}

func sensitiveIdentifierValue(resourceType, key, value string) bool {
	lowerType := strings.ToLower(resourceType)
	lowerKey := strings.ToLower(key)
	if awsAccessKeyIDRe.MatchString(value) {
		return true
	}
	if strings.Contains(lowerType, "access_key") || strings.Contains(lowerType, "secret_version") {
		return lowerKey == "id" || strings.HasSuffix(lowerKey, "_id")
	}

	return false
}

func outputIdentifierValues(raw any) []string {
	switch value := raw.(type) {
	case string:
		value = strings.TrimSpace(value)
		if isCloudIdentifierValue(value) {
			return []string{value}
		}
	case []any:
		out := []string{}
		for _, child := range value {
			out = append(out, outputIdentifierValues(child)...)
		}
		return out
	case map[string]any:
		out := []string{}
		for key, child := range value {
			if sensitiveFieldName(key) {
				continue
			}
			out = append(out, outputIdentifierValues(child)...)
		}
		return out
	}

	return nil
}

func sliceAny(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}

	return nil
}

func stringValue(v any) string {
	s, _ := v.(string)

	return s
}

func boolValue(v any) bool {
	b, _ := v.(bool)

	return b
}
