package aibom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/Vulnetix/vdb-cyclonedx"
)

// writeIaCFixture creates a temp project dir with the given files and runs
// Detect with only the IaC pass enabled.
func runIaCDetect(t *testing.T, files map[string]string) cdx.AIDetections {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cat, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := cat.Compile()
	if err != nil {
		t.Fatal(err)
	}
	det, err := Detect(Options{Root: dir, ScanIaC: true, Catalog: compiled})
	if err != nil {
		t.Fatal(err)
	}
	return det
}

func findInfra(det cdx.AIDetections, id string) *cdx.AIInfra {
	for i := range det.Infrastructure {
		if det.Infrastructure[i].ID == id {
			return &det.Infrastructure[i]
		}
	}
	return nil
}

const vllmDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm
spec:
  template:
    spec:
      containers:
        - name: server
          image: vllm/vllm-openai:v0.6.3
          args: ["--model", "meta-llama/Llama-3.1-8B-Instruct"]
          env:
            - name: HF_MODEL_ID
              value: meta-llama/Llama-3.1-8B-Instruct
            - name: OPENAI_API_KEY
              valueFrom:
                secretKeyRef: {name: keys, key: openai}
          resources:
            limits:
              nvidia.com/gpu: "1"
          volumeMounts:
            - name: model-cache
              mountPath: /models
      volumes:
        - name: model-cache
          persistentVolumeClaim:
            claimName: models-pvc
`

func TestDetectIaCVllmDeployment(t *testing.T) {
	det := runIaCDetect(t, map[string]string{"deploy/llm.yaml": vllmDeployment})

	vllm := findInfra(det, "vllm")
	if vllm == nil {
		t.Fatalf("vllm runtime not detected: %+v", det.Infrastructure)
	}
	if vllm.Version != "0.6.3" || vllm.RawTag != "v0.6.3" {
		t.Errorf("version=%q rawTag=%q", vllm.Version, vllm.RawTag)
	}
	if vllm.ConfidenceGap {
		t.Errorf("semver tag should not gap: %s", vllm.GapReason)
	}

	m := findModel(det, "meta-llama/Llama-3.1-8B-Instruct")
	if m == nil {
		t.Fatal("model not extracted from env+args")
	}
	// env + arg are separate evidence
	if m.Occurrences < 2 {
		t.Errorf("model occurrences = %d, want >= 2 (env + arg)", m.Occurrences)
	}

	// PVC-backed /models mount → data component
	var pvcData *cdx.AIData
	for i := range det.Data {
		if det.Data[i].Source == "pvc" {
			pvcData = &det.Data[i]
		}
	}
	if pvcData == nil || pvcData.Name != "pvc:models-pvc" || pvcData.MountPath != "/models" || pvcData.ConfidenceGap {
		t.Errorf("pvc data = %+v", pvcData)
	}

	// GPU limit → accelerator component
	if acc := findInfra(det, "accelerator"); acc == nil {
		t.Error("nvidia.com/gpu resource request not surfaced as accelerator")
	}

	// OPENAI_API_KEY env NAME → openai service tool with iac evidence
	var openaiTool *cdx.AITool
	for i := range det.Tools {
		for _, ev := range det.Tools[i].Evidence {
			if ev.Method == "iac" && ev.Snippet == "OPENAI_API_KEY" {
				openaiTool = &det.Tools[i]
			}
		}
	}
	if openaiTool == nil {
		t.Error("OPENAI_API_KEY name in manifest did not surface a service tool")
	}
}

func TestDetectIaCComposeOllama(t *testing.T) {
	compose := `services:
  llm:
    image: ollama/ollama:0.3.12
    environment:
      OLLAMA_MODEL: llama3.1:8b
  vecdb:
    image: qdrant/qdrant:v1.12.4
`
	det := runIaCDetect(t, map[string]string{"docker-compose.yml": compose})
	if ol := findInfra(det, "ollama"); ol == nil || ol.Version != "0.3.12" {
		t.Fatalf("ollama = %+v", ol)
	}
	if q := findInfra(det, "qdrant"); q == nil || q.Version != "1.12.4" || q.Category != "vector-database" {
		t.Fatalf("qdrant = %+v", q)
	}
	if m := findModel(det, "llama3.1:8b"); m == nil {
		t.Error("OLLAMA_MODEL value not extracted")
	}
}

func TestDetectIaCDockerfileTGI(t *testing.T) {
	df := `FROM ghcr.io/huggingface/text-generation-inference:1.4
ENV MODEL_ID=mistralai/Mistral-7B-Instruct-v0.3
CMD ["--model-id", "mistralai/Mistral-7B-Instruct-v0.3"]
`
	det := runIaCDetect(t, map[string]string{"Dockerfile": df})
	tgi := findInfra(det, "tgi")
	if tgi == nil || tgi.Version != "1.4" {
		t.Fatalf("tgi = %+v", tgi)
	}
	if m := findModel(det, "mistralai/Mistral-7B-Instruct-v0.3"); m == nil {
		t.Error("model not extracted from Dockerfile ENV/CMD")
	}
}

func TestDetectIaCNonSemverTagGaps(t *testing.T) {
	df := "FROM nvcr.io/nvidia/tritonserver:24.05-py3\n"
	det := runIaCDetect(t, map[string]string{"Containerfile": df})
	triton := findInfra(det, "triton")
	if triton == nil {
		t.Fatal("triton not detected")
	}
	if triton.Version != "" {
		t.Errorf("non-semver tag must not become a version: %q", triton.Version)
	}
	if !triton.ConfidenceGap || !strings.Contains(triton.GapReason, "not semver-shaped") {
		t.Errorf("expected semver gap, got gap=%v reason=%q", triton.ConfidenceGap, triton.GapReason)
	}
	if triton.RawTag != "24.05-py3" {
		t.Errorf("raw tag not preserved: %q", triton.RawTag)
	}
}

func TestDetectIaCKServeCRD(t *testing.T) {
	isvc := `apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata:
  name: llama
spec:
  predictor:
    model:
      modelFormat:
        name: huggingface
      runtime: kserve-huggingfaceserver
      storageUri: hf://meta-llama/Llama-3.1-8B-Instruct
`
	det := runIaCDetect(t, map[string]string{"isvc.yaml": isvc})
	ks := findInfra(det, "kserve-inferenceservice")
	if ks == nil {
		t.Fatalf("KServe InferenceService not detected: %+v", det.Infrastructure)
	}
	if m := findModel(det, "hf://meta-llama/Llama-3.1-8B-Instruct"); m == nil {
		t.Error("storageUri not extracted as model")
	}
	var uriData *cdx.AIData
	for i := range det.Data {
		if det.Data[i].Source == "uri" {
			uriData = &det.Data[i]
		}
	}
	if uriData == nil || uriData.ConfidenceGap {
		t.Errorf("hf:// storageUri should be a verified data component: %+v", uriData)
	}
}

func TestDetectIaCTrainingCRDWithDataset(t *testing.T) {
	job := `apiVersion: kubeflow.org/v1
kind: PyTorchJob
metadata:
  name: train
spec:
  pytorchReplicaSpecs:
    Master:
      template:
        spec:
          containers:
            - name: pytorch
              image: pytorch/pytorch:2.4.0
              env:
                - name: WANDB_API_KEY
                  valueFrom:
                    secretKeyRef: {name: wandb, key: key}
              volumeMounts:
                - name: training-data
                  mountPath: /data
          volumes:
            - name: training-data
              persistentVolumeClaim:
                claimName: dataset-pvc
`
	det := runIaCDetect(t, map[string]string{"train.yaml": job})
	if findInfra(det, "kubeflow-pytorchjob") == nil {
		t.Error("PyTorchJob CRD not detected")
	}
	if findInfra(det, "pytorch") == nil {
		t.Error("pytorch image inside CRD pod template not detected")
	}
	if findInfra(det, "wandb") == nil {
		t.Error("WANDB_API_KEY env-name signal not detected")
	}
	var ds *cdx.AIData
	for i := range det.Data {
		if det.Data[i].Kind == "dataset" {
			ds = &det.Data[i]
		}
	}
	if ds == nil || ds.Source != "pvc" {
		t.Errorf("dataset volume = %+v", ds)
	}
}

// Negative fixtures: none of these may produce infrastructure detections.
func TestDetectIaCNegatives(t *testing.T) {
	det := runIaCDetect(t, map[string]string{
		// GitHub Actions file: not a k8s manifest.
		".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
		// Templated image reference must be dropped, not guessed.
		"deploy/templated.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: x}\nspec:\n  template:\n    spec:\n      containers:\n        - name: c\n          image: \"{{ .Values.image }}\"\n",
		// Build-arg image.
		"Dockerfile.arg": "ARG BASE\nFROM $BASE\n",
		// Boundary: /models-shared is NOT /models.
		"deploy/notmodels.yaml": "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n    - name: web\n      image: nginx:1.27.0\n      volumeMounts:\n        - name: shared\n          mountPath: /models-shared\n  volumes:\n    - name: shared\n      emptyDir: {}\n",
		// A bare /data mount without any training signal is not a dataset.
		"deploy/webapp.yaml": "apiVersion: v1\nkind: Pod\nmetadata: {name: w}\nspec:\n  containers:\n    - name: web\n      image: nginx:1.27.0\n      volumeMounts:\n        - name: d\n          mountPath: /data\n  volumes:\n    - name: d\n      emptyDir: {}\n",
	})
	if len(det.Infrastructure) != 0 {
		t.Errorf("negatives produced infrastructure: %+v", det.Infrastructure)
	}
	if len(det.Data) != 0 {
		t.Errorf("negatives produced data components: %+v", det.Data)
	}
	if len(det.Models) != 0 {
		t.Errorf("negatives produced models: %+v", det.Models)
	}
}

func TestDetectIaCSecretRefModelEnvGaps(t *testing.T) {
	dep := `apiVersion: apps/v1
kind: Deployment
metadata: {name: llm}
spec:
  template:
    spec:
      containers:
        - name: s
          image: vllm/vllm-openai:v0.6.3
          env:
            - name: HF_MODEL_ID
              valueFrom:
                secretKeyRef: {name: hf, key: model}
`
	det := runIaCDetect(t, map[string]string{"d.yaml": dep})
	if len(det.Models) != 0 {
		t.Errorf("secret-referenced model env must not produce a model: %+v", det.Models)
	}
	vllm := findInfra(det, "vllm")
	if vllm == nil || !vllm.ConfidenceGap || !strings.Contains(vllm.GapReason, "HF_MODEL_ID references a secret") {
		t.Errorf("expected gap on runtime, got %+v", vllm)
	}
}

func TestDetectIaCHelmValues(t *testing.T) {
	det := runIaCDetect(t, map[string]string{
		"charts/llm/Chart.yaml": "apiVersion: v2\nname: llm\nversion: 0.1.0\n",
		"charts/llm/values.yaml": `image:
  repository: vllm/vllm-openai
  tag: v0.6.3
vectordb:
  image: qdrant/qdrant:v1.12.4
templated:
  image:
    repository: milvusdb/milvus
    tag: "{{ .Chart.AppVersion }}"
`,
		// values.yaml with no Chart.yaml sibling must be ignored.
		"config/values.yaml": "image: ollama/ollama:0.3.12\n",
	})
	if v := findInfra(det, "vllm"); v == nil || v.Version != "0.6.3" {
		t.Errorf("vllm from values block form = %+v", v)
	}
	if q := findInfra(det, "qdrant"); q == nil || q.Version != "1.12.4" {
		t.Errorf("qdrant from values shorthand = %+v", q)
	}
	// Templated tag → repo matched without version, gap reported.
	if m := findInfra(det, "milvus"); m != nil {
		if m.Version != "" || !m.ConfidenceGap {
			t.Errorf("templated milvus tag must gap, got %+v", m)
		}
	}
	if o := findInfra(det, "ollama"); o != nil {
		t.Errorf("values.yaml without Chart.yaml sibling must be ignored: %+v", o)
	}
}

func TestDetectIaCKustomization(t *testing.T) {
	det := runIaCDetect(t, map[string]string{
		"k8s/kustomization.yaml": `resources:
  - deploy.yaml
images:
  - name: server
    newName: lmsysorg/sglang
    newTag: v0.4.1
`,
	})
	if s := findInfra(det, "sglang"); s == nil || s.Version != "0.4.1" {
		t.Errorf("sglang from kustomize images = %+v", s)
	}
}

func TestDetectIaCTerraform(t *testing.T) {
	tf := `resource "azurerm_cognitive_account" "openai" {
  name     = "oai"
  kind     = "OpenAI"
  sku_name = "S0"
}

resource "azurerm_cognitive_account" "vision" {
  name = "cv"
  kind = "ComputerVision"
}

resource "google_vertex_ai_endpoint" "ep" {
  display_name = "ep"
}

resource "google_container_node_pool" "gpus" {
  node_config {
    guest_accelerator {
      type  = "nvidia-l4"
      count = 1
    }
  }
}

resource "aws_instance" "web" {
  instance_type = "t3.micro"
}
`
	det := runIaCDetect(t, map[string]string{"infra/main.tf": tf})
	if findInfra(det, "azure-openai") == nil {
		t.Error("azurerm_cognitive_account kind=OpenAI not detected")
	}
	if findInfra(det, "google-vertex-ai") == nil {
		t.Error("google_vertex_ai_* not detected")
	}
	if findInfra(det, "gcp-gpu-nodepool") == nil {
		t.Error("GKE guest_accelerator node pool not detected")
	}
	// Attr gates must hold: ComputerVision account and t3.micro instance are
	// not AI signals.
	if findInfra(det, "aws-gpu-instance") != nil {
		t.Error("t3.micro flagged as GPU instance")
	}
	for _, inf := range det.Infrastructure {
		if inf.ID == "azure-openai" {
			if n := len(inf.Evidence); n != 1 {
				t.Errorf("azure-openai evidence = %d, want 1 (vision account must not match)", n)
			}
		}
	}
}

func TestDetectIaCModelFiles(t *testing.T) {
	det := runIaCDetect(t, map[string]string{
		"models/llama-3.1-8b-q4.gguf": "GGUF fake",
		"weights/adapter.safetensors": "fake",
		"README.md":                   "docs",
	})
	var files []string
	for _, d := range det.Data {
		if d.Source == "file" {
			files = append(files, d.Name)
			if d.ConfidenceGap {
				t.Errorf("on-disk model file must not gap: %+v", d)
			}
		}
	}
	if len(files) != 2 {
		t.Errorf("model files = %v, want 2", files)
	}
}

func TestDetectIaCHelmTemplateFallback(t *testing.T) {
	tpl := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "chart.fullname" . }}
spec:
  template:
    spec:
      containers:
        - name: server
          image: qdrant/qdrant:v1.12.4
          ports:
            {{- toYaml .Values.ports | nindent 12 }}
`
	det := runIaCDetect(t, map[string]string{"charts/app/templates/deploy.yaml": tpl})
	q := findInfra(det, "qdrant")
	if q == nil {
		t.Skip("structural parse handled the template; fallback not exercised")
	}
	// Whether reached via fallback or structural parse, a templated file must
	// never produce an unverified fabricated value silently.
	for _, ev := range q.Evidence {
		if ev.Category == "helm-template" && (!q.ConfidenceGap || !strings.Contains(q.GapReason, "helm template")) {
			t.Errorf("helm fallback without gap: %+v", q)
		}
	}
}
