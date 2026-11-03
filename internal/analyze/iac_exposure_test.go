package analyze

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestTerraformExposure(t *testing.T) {
	cases := []struct {
		name string
		typ  string
		body string
		want string // "" means not evaluated
	}{
		// Load balancers.
		{"lb internal = false", "aws_lb", `internal = false` + "\n" + `name = "x"`, exposurePublic},
		{"lb internal = true", "aws_lb", `internal = true`, exposureInternal},
		{"lb default is internet-facing", "aws_lb", `name = "x"`, exposurePublic},
		{"lb internal from a variable", "aws_lb", `internal = var.internal`, exposureUnknown},
		{"lb internal commented out", "aws_alb", "# internal = true\nname = \"x\"", exposurePublic},
		{"classic elb internal", "aws_elb", `internal = true`, exposureInternal},

		// Lambda function URLs.
		{"lambda url none", "aws_lambda_function_url", `authorization_type = "NONE"`, exposurePublic},
		{"lambda url iam", "aws_lambda_function_url", `authorization_type = "AWS_IAM"`, exposureInternal},
		{"lambda url variable", "aws_lambda_function_url", `authorization_type = var.auth`, exposureUnknown},

		// Security groups: ingress only.
		{"sg open ingress block", "aws_security_group", "ingress {\n  from_port = 443\n  cidr_blocks = [\"0.0.0.0/0\"]\n}", exposurePublic},
		{"sg open ipv6 ingress", "aws_security_group", "ingress {\n  ipv6_cidr_blocks = [\"::/0\"]\n}", exposurePublic},
		{"sg open egress only is not exposure", "aws_security_group", "ingress {\n  cidr_blocks = [\"10.0.0.0/8\"]\n}\negress {\n  cidr_blocks = [\"0.0.0.0/0\"]\n}", exposureInternal},
		{"sg private ranges only", "aws_security_group", "ingress {\n  cidr_blocks = [\"10.0.0.0/16\", \"192.168.1.0/24\", \"172.20.0.0/14\"]\n}", exposureInternal},
		{"sg partner range is not private and not world", "aws_security_group", "ingress {\n  cidr_blocks = [\"203.0.113.0/24\"]\n}", exposureUnknown},
		{"sg cidr from a variable", "aws_security_group", "ingress {\n  cidr_blocks = var.allowed\n}", exposureUnknown},
		{"sg dynamic ingress", "aws_security_group", "dynamic \"ingress\" {\n  for_each = var.ports\n  content {\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}", exposurePublic},
		{"sg ingress as a list attribute", "aws_security_group", `ingress = [{ cidr_blocks = ["0.0.0.0/0"] }]`, exposurePublic},
		{"sg without ingress", "aws_security_group", `name = "x"`, exposureUnknown},
		{"sg rule ingress open", "aws_security_group_rule", `type = "ingress"` + "\n" + `cidr_blocks = ["0.0.0.0/0"]`, exposurePublic},
		{"sg rule egress open is skipped", "aws_security_group_rule", `type = "egress"` + "\n" + `cidr_blocks = ["0.0.0.0/0"]`, ""},
		{"vpc ingress rule v4", "aws_vpc_security_group_ingress_rule", `cidr_ipv4 = "0.0.0.0/0"`, exposurePublic},
		{"vpc ingress rule private", "aws_vpc_security_group_ingress_rule", `cidr_ipv4 = "10.1.0.0/16"`, exposureInternal},
		{"vpc egress rule is not evaluated", "aws_vpc_security_group_egress_rule", `cidr_ipv4 = "0.0.0.0/0"`, ""},

		// Public IP associations.
		{"eip association", "aws_eip_association", `instance_id = aws_instance.a.id`, exposurePublic},
		{"eip on an instance", "aws_eip", `instance = aws_instance.a.id`, exposurePublic},
		{"unattached eip", "aws_eip", `domain = "vpc"`, exposureUnknown},
		{"instance public ip", "aws_instance", `associate_public_ip_address = true`, exposurePublic},
		{"instance private ip", "aws_instance", `associate_public_ip_address = false`, exposureInternal},
		{"instance unspecified", "aws_instance", `ami = "x"`, exposureUnknown},
		{"launch template nic", "aws_launch_template", "network_interfaces {\n  associate_public_ip_address = true\n}", exposurePublic},

		// Databases.
		{"rds public", "aws_db_instance", `publicly_accessible = true`, exposurePublic},
		{"rds private", "aws_db_instance", `publicly_accessible = false`, exposureInternal},
		{"rds default", "aws_db_instance", `engine = "postgres"`, exposureUnknown},
		{"redshift public", "aws_redshift_cluster", `publicly_accessible = true`, exposurePublic},

		// Not network-facing at all.
		{"iam role", "aws_iam_role", `name = "x"`, ""},
		{"s3 bucket", "aws_s3_bucket", `bucket = "x"`, ""},
	}
	for _, c := range cases {
		got, ok := terraformExposure(c.typ, c.body)
		if c.want == "" {
			require.False(t, ok, "%s: not evaluated", c.name)

			continue
		}
		require.True(t, ok, c.name)
		require.Equal(t, c.want, got, c.name)
	}
}

func TestCloudFormationExposure(t *testing.T) {
	yamlOf := func(s string) map[string]any {
		var doc map[string]any
		require.NoError(t, yamlUnmarshal(s, &doc))

		return doc
	}
	cases := []struct {
		name, typ, yaml, want string
	}{
		{"alb internet-facing", "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties:\n  Scheme: internet-facing", exposurePublic},
		{"alb internal", "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties:\n  Scheme: internal", exposureInternal},
		{"alb default", "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties:\n  Name: x", exposurePublic},
		{"alb scheme from a parameter", "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties:\n  Scheme: !Ref SchemeParam", exposureUnknown},
		{"lambda url none", "AWS::Lambda::Url", "Properties:\n  AuthType: NONE", exposurePublic},
		{"lambda url iam", "AWS::Lambda::Url", "Properties:\n  AuthType: AWS_IAM", exposureInternal},
		{"sam function url none", "AWS::Serverless::Function", "Properties:\n  FunctionUrlConfig:\n    AuthType: NONE", exposurePublic},
		{"sam function without a url is not evaluated", "AWS::Serverless::Function", "Properties:\n  Handler: x", ""},
		{"sg world ingress", "AWS::EC2::SecurityGroup", "Properties:\n  SecurityGroupIngress:\n    - IpProtocol: tcp\n      CidrIp: 0.0.0.0/0\n  SecurityGroupEgress:\n    - CidrIp: 10.0.0.0/8", exposurePublic},
		{"sg ipv6 world ingress", "AWS::EC2::SecurityGroup", "Properties:\n  SecurityGroupIngress:\n    - CidrIpv6: '::/0'", exposurePublic},
		{"sg private ingress, open egress", "AWS::EC2::SecurityGroup", "Properties:\n  SecurityGroupIngress:\n    - CidrIp: 10.0.0.0/8\n  SecurityGroupEgress:\n    - CidrIp: 0.0.0.0/0", exposureInternal},
		{"sg ingress resource", "AWS::EC2::SecurityGroupIngress", "Properties:\n  CidrIp: 0.0.0.0/0", exposurePublic},
		{"eip association", "AWS::EC2::EIPAssociation", "Properties:\n  InstanceId: i-1", exposurePublic},
		{"instance public ip", "AWS::EC2::Instance", "Properties:\n  NetworkInterfaces:\n    - AssociatePublicIpAddress: true\n      DeviceIndex: 0", exposurePublic},
		{"instance private", "AWS::EC2::Instance", "Properties:\n  NetworkInterfaces:\n    - AssociatePublicIpAddress: false", exposureInternal},
		{"rds public", "AWS::RDS::DBInstance", "Properties:\n  PubliclyAccessible: true", exposurePublic},
		{"rds private", "AWS::RDS::DBInstance", "Properties:\n  PubliclyAccessible: false", exposureInternal},
		{"rds string true", "AWS::RDS::DBInstance", "Properties:\n  PubliclyAccessible: 'true'", exposurePublic},
		{"bucket is not evaluated", "AWS::S3::Bucket", "Properties:\n  BucketName: x", ""},
	}
	for _, c := range cases {
		got, ok := cloudFormationExposure(c.typ, yamlOf(c.yaml))
		if c.want == "" {
			require.False(t, ok, c.name)

			continue
		}
		require.True(t, ok, c.name)
		require.Equal(t, c.want, got, c.name)
	}
}

func TestKubernetesExposure(t *testing.T) {
	cases := []struct {
		name, kind, yaml, want string
	}{
		{"loadbalancer service", "Service", "spec:\n  type: LoadBalancer", exposurePublic},
		{"nodeport service", "Service", "spec:\n  type: NodePort", exposurePublic},
		{"clusterip service", "Service", "spec:\n  type: ClusterIP", exposureInternal},
		{"default service type", "Service", "spec:\n  ports: []", exposureInternal},
		{"headless service", "Service", "spec:\n  clusterIP: None", exposureInternal},
		{"externalname", "Service", "spec:\n  type: ExternalName", exposureUnknown},
		{"internal aws nlb", "Service", "metadata:\n  annotations:\n    service.beta.kubernetes.io/aws-load-balancer-scheme: internal\nspec:\n  type: LoadBalancer", exposureInternal},
		{"internal azure lb", "Service", "metadata:\n  annotations:\n    service.beta.kubernetes.io/azure-load-balancer-internal: 'true'\nspec:\n  type: LoadBalancer", exposureInternal},
		{"internal gke lb", "Service", "metadata:\n  annotations:\n    networking.gke.io/load-balancer-type: Internal\nspec:\n  type: LoadBalancer", exposureInternal},
		{"ingress", "Ingress", "spec:\n  rules: []", exposurePublic},
		{"internal alb ingress", "Ingress", "metadata:\n  annotations:\n    alb.ingress.kubernetes.io/scheme: internal", exposureInternal},
		{"internal ingress class", "Ingress", "spec:\n  ingressClassName: nginx-internal", exposureInternal},
		{"deployment is not evaluated", "Deployment", "spec:\n  replicas: 1", ""},
	}
	for _, c := range cases {
		var doc map[string]any
		require.NoError(t, yamlUnmarshal(c.yaml, &doc), c.name)
		got, ok := kubernetesExposure(c.kind, doc)
		if c.want == "" {
			require.False(t, ok, c.name)

			continue
		}
		require.True(t, ok, c.name)
		require.Equal(t, c.want, got, c.name)
	}
}

// End to end: the property reaches the node and the edge for each platform, and a resource
// that is not network-facing carries none.
func TestCollectInfrastructure_EmitsExposure(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	}
	write("infra/main.tf", `
resource "aws_lb" "front" {
  internal = false
}
resource "aws_lb" "back" {
  internal = true
}
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_lambda_function_url" "hook" {
  authorization_type = "AWS_IAM"
}
resource "aws_iam_role" "r" {
  name = "r"
}
`)
	write("infra/stack.yaml", `
Resources:
  Api:
    Type: AWS::Lambda::Url
    Properties:
      AuthType: NONE
  Bucket:
    Type: AWS::S3::Bucket
`)
	write("k8s/svc.yaml", `
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  type: LoadBalancer
---
apiVersion: v1
kind: Service
metadata:
  name: db
spec:
  type: ClusterIP
`)
	files := &fileStats{}
	b := NewBuilder(Tool{Name: "test", Version: "dev"}, Target{RepoID: "acme/demo", RootPath: dir}, time.Now())
	st := collectContracts(b, dir, files, nil, Target{RepoID: "acme/demo"})

	got := map[string]any{}
	hasProp := map[string]bool{}
	for _, n := range st.nodes {
		if n.Kind != "iac_resource" {
			continue
		}
		v, ok := n.Properties["exposure"]
		hasProp[n.Name] = ok
		got[n.Name] = v
	}
	require.Equal(t, exposurePublic, got["aws_lb.front"])
	require.Equal(t, exposureInternal, got["aws_lb.back"])
	require.Equal(t, exposurePublic, got["aws_security_group.web"])
	require.Equal(t, exposureInternal, got["aws_lambda_function_url.hook"])
	require.False(t, hasProp["aws_iam_role.r"], "an IAM role is not network-facing")
	require.Equal(t, exposurePublic, got["Api"])
	require.False(t, hasProp["Bucket"])
	require.Equal(t, exposurePublic, got["Service/web"])
	require.Equal(t, exposureInternal, got["Service/db"])
}

func yamlUnmarshal(s string, v any) error { return yaml.Unmarshal([]byte(s), v) }
