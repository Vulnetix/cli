---
title: "AI SDKs & Frameworks"
weight: 2
description: "AI SDKs detected by the source-code pass and the model-name parameters extracted from each."
---

The source-code pass scans files in the matching language for these SDKs. When an SDK is in use, the catalog extracts the model-name literal bound to the listed parameters — so unknown / future model names are captured without a hardcoded model list.

> Generated from the catalog. To add an SDK, edit `internal/aibom/catalog/libraries.json` and run `just gen-aibom`.

| Library | Provider | Languages | Model parameters |
|---------|----------|-----------|------------------|
| ai21 | AI21 Labs | python | `model` |
| @aws-sdk/client-bedrock-runtime | AWS Bedrock | javascript | `modelId` |
| aws-sdk-go-v2 bedrockruntime | AWS Bedrock | go | `ModelId` |
| boto3 (AWS Bedrock) | AWS Bedrock | python | `modelId` |
| langchain-aws | AWS Bedrock | python | `model_id` |
| agno | Agno | python | `id` |
| @anthropic-ai/sdk | Anthropic | javascript | `model` |
| Anthropic.SDK / Anthropic | Anthropic | csharp | — |
| anthropic | Anthropic | python | `model` |
| anthropic (Rust) | Anthropic | rust | — |
| anthropic (official Ruby SDK) | Anthropic | ruby | `model` |
| anthropic-java (official) | Anthropic | java | `model` |
| anthropic-php (official SDK) | Anthropic | php | `model` |
| anthropic-sdk-go | Anthropic | go | `Model` |
| azure-ai-inference | Azure AI Inference | python | `model` |
| azure openai | Azure OpenAI | python | `deployment` |
| @cerebras/cerebras_cloud_sdk | Cerebras | javascript | `model` |
| Cloudflare Workers AI | Cloudflare Workers AI | javascript, bash, go, python | `model` |
| cohere | Cohere | python | `model` |
| cohere-ai | Cohere | javascript | `model` |
| langchain-cohere | Cohere | python | `model` |
| crewai | CrewAI | python | `model` |
| dspy | DSPy | python | `model` |
| fireworks-ai | Fireworks AI | python | `model` |
| @google/genai | Google | javascript | `model` |
| @google/generative-ai | Google | javascript | `model` |
| google-gemini-php | Google | php | `model` |
| google-genai | Google | python | `model` |
| google-genai (Java) | Google | java | `model` |
| google-generativeai | Google | python | `model` |
| google.golang.org/genai | Google | go | `model` |
| genkit | Google Genkit | javascript | `model` |
| @google-cloud/vertexai | Google Vertex AI | javascript | `model` |
| vertexai | Google Vertex AI | python | `model` |
| griptape | Griptape | python | `model` |
| groq | Groq | python | `model` |
| groq-sdk | Groq | javascript | `model` |
| langchain-groq | Groq | python | `model` |
| guidance | Guidance | python | `model` |
| @huggingface/inference | Hugging Face | javascript | `model` |
| huggingface_hub | Hugging Face | python | `model` |
| smolagents | Hugging Face | python | `model_id` |
| transformers | Hugging Face | python | `model`, `pretrained` |
| ibm-watsonx-ai | IBM watsonx.ai | python | `model_id` |
| instructor | Instructor | python | `model`, `provider-model` |
| @langchain | LangChain | javascript | `model` |
| langchain | LangChain | python | `model`, `model_name` |
| langchain-anthropic | LangChain | python | `model` |
| langchain-google-genai | LangChain | python | `model` |
| langchain-mistralai | LangChain | python | `model` |
| langchain-openai | LangChain | python | `model` |
| langchaingo | LangChain | go | `model` |
| langchainrb | LangChain | ruby | `chat_model`, `model` |
| langgraph | LangChain | python | `model` |
| langchain4j | LangChain4j | java | `modelName` |
| litellm | LiteLLM | python | `model` |
| llama-index | LlamaIndex | python | `model` |
| llamaindex | LlamaIndex | javascript | `model` |
| magentic | Magentic | python | `model` |
| marvin | Marvin | python | `model` |
| @mastra/core | Mastra | javascript | `model` |
| autogen | Microsoft AutoGen | python | `model` |
| Microsoft.SemanticKernel | Microsoft Semantic Kernel | csharp | `deploymentName`, `modelId` |
| semantic-kernel | Microsoft Semantic Kernel | python | `model_id` |
| mirascope | Mirascope | python | `model` |
| @mistralai/mistralai | Mistral AI | javascript | `model` |
| mistralai | Mistral AI | python | `model` |
| langchain-ollama | Ollama | python | `model` |
| ollama | Ollama | javascript | `model` |
| ollama | Ollama | python | `model` |
| ollama (Go client) | Ollama | go | `Model` |
| ollama-rs | Ollama | rust | `model` |
| OpenAI (MacPaw) | OpenAI | swift | `model` |
| OpenAI / Azure.AI.OpenAI | OpenAI | csharp | `deployment`, `model` |
| async-openai | OpenAI | rust | `model` |
| go-openai | OpenAI | go | `Model` |
| openai | OpenAI | python | `deployment`, `model` |
| openai | OpenAI | javascript | `model` |
| openai-agents | OpenAI | python | `model` |
| openai-go (official) | OpenAI | go | `Model` |
| openai-java | OpenAI | java | `model` |
| openai-kotlin | OpenAI | kotlin | `model` |
| openai-php | OpenAI | php | `model` |
| ruby-openai | OpenAI | ruby | `model` |
| @openrouter/ai-sdk-provider | OpenRouter | javascript | `model` |
| outlines | Outlines | python | `model` |
| pydantic-ai | Pydantic AI | python | `model` |
| replicate | Replicate | python | `ref` |
| replicate | Replicate | javascript | `ref` |
| ruby_llm | RubyLLM | ruby | `model` |
| sglang | SGLang | python | `model_path` |
| sentence-transformers | Sentence Transformers | python | `model` |
| Spring AI | Spring AI | java | `model` |
| together | Together AI | python | `model` |
| together-ai | Together AI | javascript | `model` |
| ai (Vercel AI SDK) | Vercel | javascript | `model`, `provider-model` |
| voyageai | Voyage AI | javascript | `model` |
| haystack-ai | deepset Haystack | python | `model` |
| @fal-ai/client | fal.ai | javascript | `ref` |
| llama-cpp-python | llama.cpp | python | `repo_id` |
| rig | rig | rust | — |
| vllm | vLLM | python | `model` |
