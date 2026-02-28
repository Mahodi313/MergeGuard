MergeGuard is an AI-powered pull request risk analysis tool for C#/.NET projects.

It integrates with the SDLC by analyzing code changes from pull requests and generating a structured risk report, including:

Risk score (0–100)

Risk level (Low / Medium / High)

Key risk factors

Recommended validation tests

The system validates GitHub webhooks, processes change diffs, and uses a local LLM (Ollama) to produce consistent, structured JSON output suitable for automated merge gates and release decision support.
