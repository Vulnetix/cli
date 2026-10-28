package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func env(vars map[string]string) Env {
	return func(k string) string { return vars[k] }
}

func TestProbeLambdaAndFargate(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	imdsBase = "http://127.0.0.1:1" // nothing listens: not EC2

	if f := Probe(ctx, env(map[string]string{"AWS_LAMBDA_FUNCTION_NAME": "api"}), root, nil); f.ComputeKind != "lambda" || f.Hostname != "api" {
		t.Fatalf("lambda = %+v", f)
	}

	ecs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"TaskARN":"arn:aws:ecs:us-east-1:1:task/c/abc","LaunchType":"FARGATE"}`))
	}))
	defer ecs.Close()
	f := Probe(ctx, env(map[string]string{"ECS_CONTAINER_METADATA_URI_V4": ecs.URL}), root, nil)
	if f.ComputeKind != "ecs-fargate" || f.ResourceArn != "arn:aws:ecs:us-east-1:1:task/c/abc" {
		t.Fatalf("fargate = %+v", f)
	}

	if f := Probe(ctx, env(nil), root, nil); f.ComputeKind != "host" {
		t.Fatalf("plain host = %+v", f)
	}
}

func TestProbeEC2AndEMR(t *testing.T) {
	imds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			_, _ = w.Write([]byte("tok"))

			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}
		_, _ = w.Write([]byte(`{"instanceId":"i-0abc","region":"ap-southeast-2","accountId":"111122223333"}`))
	}))
	defer imds.Close()
	imdsBase = imds.URL

	root := t.TempDir()
	f := Probe(context.Background(), env(nil), root, nil)
	if f.ComputeKind != "ec2" || f.ResourceArn != "arn:aws:ec2:ap-southeast-2:111122223333:instance/i-0abc" {
		t.Fatalf("ec2 = %+v", f)
	}

	if err := os.MkdirAll(filepath.Join(root, "mnt/var/lib/info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "mnt/var/lib/info/instance.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if f := Probe(context.Background(), env(nil), root, nil); f.ComputeKind != "emr" {
		t.Fatalf("emr = %+v", f)
	}
}

func TestSensorKeyIsStable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	a, err := SensorKey(dir)
	if err != nil || len(a) != 32 {
		t.Fatalf("key = %q %v", a, err)
	}
	b, _ := SensorKey(dir)
	if a != b {
		t.Fatal("a restart must keep the same key")
	}
	info, _ := os.Stat(filepath.Join(dir, "sensor-key"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v", info.Mode().Perm())
	}
}
