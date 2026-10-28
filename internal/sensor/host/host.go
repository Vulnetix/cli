// Package host answers what the sensor is running on: the compute kind, the
// ARN of the resource when one can be read, the kernel, and a stable sensor
// key kept on disk so a restart re-registers the same sensor.
//
// Every probe is bounded by a short timeout and fails to "unknown" rather
// than blocking start-up: a sensor that cannot tell it is on EC2 still runs.
package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Facts is what the sensor reports about where it runs.
type Facts struct {
	ComputeKind   string
	ResourceArn   string
	Hostname      string
	KernelVersion string
}

// Env reads environment variables; os.Getenv outside tests.
type Env func(string) string

// Probe gathers Facts. root is the filesystem to read (normally "/").
func Probe(ctx context.Context, env Env, root string, client *http.Client) Facts {
	if env == nil {
		env = os.Getenv
	}
	if client == nil {
		client = &http.Client{Timeout: time.Second}
	}
	f := Facts{KernelVersion: kernel(root)}
	f.Hostname, _ = os.Hostname()

	switch {
	case env("AWS_LAMBDA_FUNCTION_NAME") != "":
		f.ComputeKind = "lambda"
		f.Hostname = env("AWS_LAMBDA_FUNCTION_NAME")
	case env("ECS_CONTAINER_METADATA_URI_V4") != "":
		f.ComputeKind, f.ResourceArn = ecsTask(ctx, client, env("ECS_CONTAINER_METADATA_URI_V4"))
	case env("KUBERNETES_SERVICE_HOST") != "":
		f.ComputeKind = "eks-node"
		f.ResourceArn = ec2Arn(ctx, client)
	case exists(filepath.Join(root, "mnt/var/lib/info/instance.json")):
		// EMR writes its node description here on every cluster node.
		f.ComputeKind = "emr"
		f.ResourceArn = ec2Arn(ctx, client)
	default:
		if arn := ec2Arn(ctx, client); arn != "" {
			f.ComputeKind, f.ResourceArn = "ec2", arn
		} else {
			f.ComputeKind = "host"
		}
	}

	return f
}

func kernel(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "proc/sys/kernel/osrelease"))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(b))
}

// ecsTask reads the task metadata endpoint for the launch type and task ARN.
func ecsTask(ctx context.Context, client *http.Client, base string) (string, string) {
	var task struct {
		TaskARN    string `json:"TaskARN"`
		LaunchType string `json:"LaunchType"`
	}
	if err := getJSON(ctx, client, strings.TrimRight(base, "/")+"/task", nil, &task); err != nil {
		return "ecs-ec2", ""
	}
	if strings.EqualFold(task.LaunchType, "FARGATE") {
		return "ecs-fargate", task.TaskARN
	}

	return "ecs-ec2", task.TaskARN
}

// imdsBase is the EC2 instance metadata service.
var imdsBase = "http://169.254.169.254"

// ec2Arn asks IMDSv2 for the instance identity. "" when not on EC2, or when
// the hop limit stops a container reaching it.
func ec2Arn(ctx context.Context, client *http.Client) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, imdsBase+"/latest/api/token", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	token, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var doc struct {
		InstanceID string `json:"instanceId"`
		Region     string `json:"region"`
		AccountID  string `json:"accountId"`
	}
	if err := getJSON(ctx, client, imdsBase+"/latest/dynamic/instance-identity/document",
		map[string]string{"X-aws-ec2-metadata-token": string(token)}, &doc); err != nil || doc.InstanceID == "" {
		return ""
	}

	return "arn:aws:ec2:" + doc.Region + ":" + doc.AccountID + ":instance/" + doc.InstanceID
}

func getJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func exists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}

// SensorKey returns the key stored in dir, creating it on first run. The key
// is random, not derived from the host, so nothing about the machine is in it.
func SensorKey(dir string) (string, error) {
	path := filepath.Join(dir, "sensor-key")
	if b, err := os.ReadFile(path); err == nil {
		if key := strings.TrimSpace(string(b)); key != "" {
			return key, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	key := hex.EncodeToString(b[:])
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return "", err
	}

	return key, nil
}
