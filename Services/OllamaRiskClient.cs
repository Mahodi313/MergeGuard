using MergeGuard.Models;
using System.Text.Json;

namespace MergeGuard.Services
{
    public sealed class OllamaRiskClient
    {
        private readonly HttpClient _http;
        private readonly IConfiguration _config;

        public OllamaRiskClient(HttpClient http, IConfiguration config)
        {
            _http = http;
            _config = config;
        }

        public async Task<RiskReport> AnalyzeAsync(string changeText, CancellationToken ct = default)
        {

            // TEST comment
            var model = _config["Ollama:Model"] ?? "gemma3:4b";

            // Prompt
            var system = """
            You are a senior C#/.NET reviewer focused on merge risk.
            Return ONLY valid JSON. No markdown. No extra text.
            Schema:
            {
              "riskScore": 0,
              "riskLevel": "Low|Medium|High",
              "reasons": ["..."],
              "recommendedTests": ["..."]
            }
            Rules:
            - riskScore is integer 0-100
            - 3-6 reasons, short and evidence-based
            - 3-6 recommendedTests, actionable
            """;

            var user = $"""
            Analyze this change and output the JSON schema above.

            CHANGE:
            {changeText}
            """;

            // Call Ollama chat endpoint
            var req = new
            {
                model,
                messages = new[]
                {
                new { role = "system", content = system },
                new { role = "user", content = user }
            },
                stream = false,

                format = new
                {
                    type = "object",
                    properties = new
                    {
                        riskScore = new { type = "integer" },
                        riskLevel = new { type = "string" },
                        reasons = new { type = "array", items = new { type = "string" } },
                        recommendedTests = new { type = "array", items = new { type = "string" } }
                    },

                    required = new[] { "riskScore", "riskLevel", "reasons", "recommendedTests" }
                }
            };

            // test 2323
            var resp = await _http.PostAsJsonAsync("chat", req, ct);
            resp.EnsureSuccessStatusCode();
            var raw = await resp.Content.ReadAsStringAsync(ct);
            Console.WriteLine("OLLAMA RAW RESPONSE:");
            Console.WriteLine(raw);

            // Ollama returns JSON
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            var content = doc.RootElement.GetProperty("message").GetProperty("content").GetRawText();

            if (string.IsNullOrWhiteSpace(content))
                return new RiskReport { RiskScore = 0, RiskLevel = "Low", Reasons = ["No model output"], RecommendedTests = [] };

            // Parse the model into RiskReport
            try
            {
                return JsonSerializer.Deserialize<RiskReport>(
                    content,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                )!;
            }
            catch
            {
                return new RiskReport
                {
                    RiskScore = 0,
                    RiskLevel = "Low",
                    Reasons = ["Model did not return valid JSON (prompt/output mismatch)."],
                    RecommendedTests = ["Adjust prompt to enforce JSON-only output."]
                };
            }
        }
    }
}
