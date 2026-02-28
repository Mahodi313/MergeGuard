using MergeGuard.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MergeGuard.Controllers
{
    [ApiController]
    [Route("webhook/github")]
    public class GitHubWebhookController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly OllamaRiskClient _ollama;
        private readonly ILogger<GitHubWebhookController> _logger;

        public GitHubWebhookController(IConfiguration config, OllamaRiskClient ollama, ILogger<GitHubWebhookController> logger)
        {
            _config = config;
            _ollama = ollama;
            _logger = logger;
        }

        [HttpPost]
        public async Task<IActionResult> Handle(CancellationToken ct)
        {
            byte[] bodyBytes;
            using (var ms = new MemoryStream())
            {
                await Request.Body.CopyToAsync(ms, ct);
                bodyBytes = ms.ToArray();
            }

            var eventName = Request.Headers["X-GitHub-Event"].ToString();
            var deliveryId = Request.Headers["X-GitHub-Delivery"].ToString();
            var signature = Request.Headers["X-Hub-Signature-256"].ToString();

            _logger.LogInformation("Received GitHub webhook: Event={Event}, DeliveryId={DeliveryId}", eventName, deliveryId);

            var secret = _config["GitHub:WebhookSecret"];
            if (string.IsNullOrWhiteSpace(secret))
            {
                return StatusCode(500, "Missing GitHub:WebhookSecret in configuration.");
            }

            if (!VerifySignature(bodyBytes, secret, signature))
            {
                return Unauthorized("Invalid signature.");
            }

            using var doc = JsonDocument.Parse(bodyBytes);
            var root = doc.RootElement;

            if (!string.Equals(eventName, "pull_request", StringComparison.OrdinalIgnoreCase))
            {
                return Ok(new { ok = true, ignored = true, eventName });
            }

            var action = GetString(root, "action") ?? "unknown";
            var owner = GetString(root, "repository", "owner", "login");
            var repo = GetString(root, "repository", "name");
            var prNumber = GetInt(root, "number");
            var headSha = GetString(root, "pull_request", "head", "sha");

            _logger.LogInformation("PR webhook action={Action} repo={Owner}/{Repo} pr={PrNumber} sha={HeadSha}",
                action, owner, repo, prNumber, headSha
            );

            if (!IsActionWeCareAbout(action))
            {
                return Ok(new
                {
                    ok = true,
                    ignored = true,
                    reason = $"Action '{action}' not handled",
                    action,
                    repo = (owner is null || repo is null) ? null : $"{owner}/{repo}",
                    prNumber,
                    headSha
                });
            }

            var diff = GetString(root, "diff");

            if (string.IsNullOrWhiteSpace(diff))
            {
                return Ok(new
                {
                    ok = true,
                    action,
                    repo = (owner is null || repo is null) ? null : $"{owner}/{repo}",
                    prNumber,
                    headSha,
                    message = "No 'diff' provided in payload. Real GitHub PR webhooks do not include diffs. Implement PR file fetching next."
                });
            }

            // Analyze the diff with Ollama and get a risk report
            var report = await _ollama.AnalyzeAsync(diff, ct);

            return Ok(new
            {
                ok = true,
                eventName,
                deliveryId,
                action,
                repo = (owner is null || repo is null) ? null : $"{owner}/{repo}",
                prNumber,
                headSha,
                risk = report
            });
        }

        private static bool IsActionWeCareAbout(string action)
            => action.Equals("opened", StringComparison.OrdinalIgnoreCase)
            || action.Equals("synchronize", StringComparison.OrdinalIgnoreCase)
            || action.Equals("reopened", StringComparison.OrdinalIgnoreCase);

        private static bool VerifySignature(byte[] body, string secret, string signature256Header)
        {
            const string prefix = "sha256=";
            if (string.IsNullOrWhiteSpace(signature256Header) || !signature256Header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var theirHex = signature256Header.Substring(prefix.Length).Trim();

            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var ourHash = hmac.ComputeHash(body);
            var ourHex = ToLowerHex(ourHash);

            return FixedTimeEquals(ourHex, theirHex);
        }

        private static string ToLowerHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);

            foreach (var b in bytes)
            {
                sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }

        private static bool FixedTimeEquals(string a, string b)
        {
            if (a.Length != b.Length) return false;

            var diff = 0;

            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }

            return diff == 0;
        }

        //JSON Helpers
        private static string? GetString(JsonElement root, params string[] path)
        {
            var current = root;

            foreach (var p in path)
            {
                if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(p, out var next))
                {
                    return null;
                }
                current = next;
            }

            return current.ValueKind == JsonValueKind.String ? current.GetString() : current.GetString();
        }

        private static int? GetInt(JsonElement root, params string[] path)
        {
            var current = root;

            foreach (var p in path)
            {
                if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(p, out var next))
                {
                    return null;
                }
                current = next;
            }

            return current.ValueKind == JsonValueKind.Number && current.TryGetInt32(out var v) ? v : null;
        }
    }
}
