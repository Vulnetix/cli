---
title: "AI Infrastructure (IaC)"
weight: 3
description: "AI serving runtimes, agent platforms, vector databases and training frameworks detected from Kubernetes manifests, compose files and Dockerfiles."
---

The IaC pass analyzes **repository files** — Kubernetes manifests (including CRDs), docker-compose files and Dockerfiles — for the AI infrastructure they would produce. Every detection is validated; a value that cannot be verified from the file is either dropped (likely false positive) or reported with `vulnetix:ai/confidence-gap` = `true` and a `vulnetix:ai/gap-reason` stating exactly what could not be verified and why. **Nothing is ever guessed.**

> Generated from the catalog. To add or refine a rule, edit `internal/aibom/catalog/infrastructure.json` and run `just gen-aibom`.

## Runtimes detected by container image

Image patterns are matched against the image **name** (registry + repository, tag/digest split off). The version is reported only when the tag is semver-shaped; otherwise the raw tag is preserved and the component carries a confidence gap.

| Runtime | Category | Image patterns |
|---------|----------|----------------|
| Chainlit | `agent` | `^chainlit/chainlit$` |
| Flowise | `agent` | `^flowiseai/flowise$` |
| Haystack | `agent` | `^deepset/haystack$`, `^deepset/hayhooks$` |
| Langflow | `agent` | `^langflowai/langflow$` |
| LlamaIndex | `agent` | `^llamaindex/[\w.-]+$` |
| Open WebUI | `agent` | `^ghcr\.io/open-webui/open-webui$` |
| LM Evaluation Harness | `evaluation` | `^eleutherai/lm-eval(uation-harness)?$` |
| Ragas | `evaluation` | `^ragas/[\w.-]+$` |
| TruLens | `evaluation` | `^trulens/[\w.-]+$` |
| LMDeploy | `inference` | `^openmmlab/lmdeploy$` |
| LiteLLM Proxy | `inference` | `^ghcr\.io/berriai/litellm$` |
| LocalAI | `inference` | `^localai/localai$`, `^quay\.io/go-skynet/local-ai$` |
| NVIDIA NIM | `inference` | `^nvcr\.io/nim/[\w.-]+/[\w.-]+$` |
| Ollama | `inference` | `^ollama/ollama$` |
| Ray | `inference` | `^rayproject/ray(-ml)?$` |
| SGLang | `inference` | `^lmsysorg/sglang$` |
| Text Embeddings Inference | `inference` | `^ghcr\.io/huggingface/text-embeddings-inference$` |
| Text Generation Inference | `inference` | `^huggingface/text-generation-inference$`, `^ghcr\.io/huggingface/text-generation-inference$` |
| Triton Inference Server | `inference` | `^nvcr\.io/nvidia/tritonserver$` |
| llama.cpp server | `inference` | `^ghcr\.io/ggml-org/llama\.cpp$`, `^ghcr\.io/ggerganov/llama\.cpp$` |
| llm-d | `inference` | `^ghcr\.io/llm-d/[\w.-]+$` |
| vLLM | `inference` | `^vllm/[\w.-]+$`, `^ghcr\.io/vllm-project/[\w.-]+$` |
| Axolotl | `training` | `^axolotlai/axolotl$`, `^winglian/axolotl$` |
| Hugging Face Accelerate | `training` | `^huggingface/accelerate(-[\w.-]+)?$` |
| JAX | `training` | `^ghcr\.io/google/jax$`, `^ghcr\.io/nvidia/jax$` |
| PyTorch | `training` | `^pytorch/pytorch$`, `^nvcr\.io/nvidia/pytorch$` |
| Chroma | `vector-database` | `^chromadb/chroma$`, `^ghcr\.io/chroma-core/chroma$` |
| Milvus | `vector-database` | `^milvusdb/milvus$` |
| Qdrant | `vector-database` | `^qdrant/qdrant$` |
| Weaviate | `vector-database` | `^semitechnologies/weaviate$`, `^cr\.weaviate\.io/semitechnologies/weaviate$` |
| pgvector | `vector-database` | `^pgvector/pgvector$`, `^ankane/pgvector$` |

## Custom resources (CRDs)

| Kind | API group prefix | Category | Declared fields extracted |
|------|------------------|----------|---------------------------|
| InferenceService | `serving.kserve.io/` | `inference` | `spec.predictor.model.storageUri`, `spec.predictor.model.modelFormat.name`, `spec.predictor.model.modelFormat.version`, `spec.predictor.model.runtime`, `spec.predictor.serviceAccountName` |
| PyTorchJob | `kubeflow.org/` | `training` | pod templates (embedded) |
| TFJob | `kubeflow.org/` | `training` | pod templates (embedded) |
| RayJob | `ray.io/` | `training` | pod templates (embedded) |
| RayService | `ray.io/` | `inference` | pod templates (embedded) |
| RayCluster | `ray.io/` | `training` | pod templates (embedded) |

## Model identity signals

- **Environment values**: `HF_MODEL_ID`, `MODEL_NAME`, `MODEL_ID`, `OLLAMA_MODEL` (a `valueFrom` secret/configMap reference is never resolved — it produces a confidence gap instead)
- **Container args/command flags**: `--model`, `--model-id`, `--model_id`, `--model-path`, `--model-repository`, `--model-name`, `--served-model-name` (both `--flag value` and `--flag=value`)
- **Declared annotations**: prefixes `vulnetix.com/model.`, `model.k8saibom.dev/`
- **Volume mounts** (model artifacts): path-boundary prefixes `/models`, `/model`, `/weights`, `/checkpoints`, `/hf_cache` — `/models` matches `/models/x` but never `/models-shared`
- **Dataset volumes** (training workloads only): names `dataset`, `datasets`, `training-data`, mount prefixes `/data`

## Workload environment-name signals

Only the variable **name** is matched — values are never read.

| Env var | Framework | Category |
|---------|-----------|----------|
| `AUTOGEN_USE_DOCKER` | AutoGen | `agent` |
| `CREWAI_TELEMETRY_OPT_OUT` | CrewAI | `agent` |
| `DSPY_CACHEDIR` | DSPy | `agent` |
| `HAYSTACK_TELEMETRY_ENABLED` | Haystack | `agent` |
| `LANGCHAIN_API_KEY` | LangChain | `agent` |
| `LANGCHAIN_TRACING_V2` | LangChain | `agent` |
| `LANGSMITH_API_KEY` | LangChain | `agent` |
| `LLAMA_CLOUD_API_KEY` | LlamaIndex | `agent` |
| `MLFLOW_TRACKING_URI` | MLflow | `training` |
| `WANDB_API_KEY` | Weights & Biases | `training` |
| `WANDB_PROJECT` | Weights & Biases | `training` |

Remote AI API dependencies (e.g. `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) declared on workload containers are surfaced through the same provider-service catalog as the local environment pass.

## GPU / accelerator signals

Resource keys: `nvidia.com/gpu`, `amd.com/gpu`, `google.com/tpu`, `habana.ai/gaudi`, `intel.com/gpu`, plus node selectors mentioning `accelerator`.

## Terraform / OpenTofu signals

Matched by resource type (regex over `.tf`/`.tofu` content — resource names and variables are never interpreted). An **attribute gate** additionally requires a pattern inside the resource block, so e.g. a `ComputerVision` cognitive account never matches the Azure OpenAI signal.

| Signal | Provider | Category | Resource pattern | Attribute gate |
|--------|----------|----------|------------------|----------------|
| Google Vertex AI | Google Cloud | `managed-ai` | `^google_vertex_ai_` | — |
| Amazon Bedrock | AWS | `managed-ai` | `^aws_bedrock` | — |
| Amazon SageMaker | AWS | `managed-ai` | `^aws_sagemaker_` | — |
| Azure OpenAI Service | Microsoft Azure | `managed-ai` | `^azurerm_cognitive_account$` | `kind\s*=\s*"OpenAI"` |
| Azure AI Services | Microsoft Azure | `managed-ai` | `^azurerm_ai_services$` | — |
| GKE GPU node pool | Google Cloud | `accelerator` | `^google_container_node_pool$` | `guest_accelerator` |
| AWS GPU instance | AWS | `accelerator` | `^aws_(instance|launch_template)$` | `instance_type\s*=\s*"(p[2-5]|g[4-6]|trn[12]|inf[12])[a-z0-9]*\.` |
| Azure GPU VM | Microsoft Azure | `accelerator` | `^azurerm_(linux|windows)_virtual_machine(_scale_set)?$` | `size\s*=\s*"Standard_N` |

## Model files on disk

Weight files present in the repository (`.gguf`, `.safetensors`, `.onnx`) are reported as verified `data` components — the artifact literally exists. `.pt` is deliberately excluded (too many non-model uses).

## Known false negatives

Detection is deliberately allowlist-driven — a missed detection is preferred over a wrong one. The following are **not** detected, by design:

- Images mirrored to private or organisation-local registries (the official-registry patterns will not match a mirror).
- Helm values that are still templated (`{{ .Values.image }}`) — structural parsing skips them; the narrow regex fallback reports what it finds with an explicit confidence gap.
- Models fetched at runtime (entrypoint scripts, init downloads) that leave no declared trace in the manifest.
- Model identities passed through ConfigMaps or Secrets — references are never resolved.
- Bare `/data` mounts on workloads with no training signal (not assumed to be datasets).

Absence of a finding is therefore **not** verified absence of AI infrastructure.
