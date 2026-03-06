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
        private readonly GitHubInstallationTokenClient _installTokenClient;
        private readonly GitHubChecksClient _checksClient;
        private readonly GitHubPullRequestClient _prClient;

        public GitHubWebhookController(IConfiguration config, OllamaRiskClient ollama, ILogger<GitHubWebhookController> logger, GitHubInstallationTokenClient installationTokenClient, GitHubChecksClient checksClient, GitHubPullRequestClient prClient)
        {
            _config = config;
            _ollama = ollama;
            _logger = logger;
            _installTokenClient = installationTokenClient;
            _checksClient = checksClient;
            _prClient = prClient;
        }

        [HttpGet]
        public IActionResult Health() => Ok(new { ok = true });

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

            // Handle ping events when creating / updating webhooks in github
            if (eventName == "ping")
            {
                _logger.LogInformation("Received GitHub ping event.");
                return Ok(new { ok = true, message = "pong" });
            }

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
            var prNumber = GetInt(root, "pull_request", "number");
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

            var installationId = GetLong(root, "installation", "id");
            if (installationId is null)
            {
                return Ok(new { ok = true, message = "Missing installation.id in payload. Is the GitHub App installed on this repo?" });
            }
                
            if (string.IsNullOrWhiteSpace(owner) || string.IsNullOrWhiteSpace(repo) || string.IsNullOrWhiteSpace(headSha))
            {
                return Ok(new { ok = true, message = "Missing owner/repo/headSha in payload." });
            }
               
            // Get installation token
            var token = await _installTokenClient.CreateInstallationTokenAsync(installationId.Value, ct);

            if (prNumber is null)
            {
                return Ok(new { ok = true, message = "Missing pull_request.number in payload." });
            }

            var files = await _prClient.ListPullRequestFilesAsync(token, owner, repo, prNumber.Value, ct);

            // Build a capped input to avoid huge prompts
            var aiInput = BuildAiInput(owner, repo, prNumber.Value, headSha, files, maxChars: 12000);

            // AI risk analysis with Ollama
            var report = await _ollama.AnalyzeAsync(aiInput, ct);

            // Post the result back to github as a check run
            var conclusion = report.RiskLevel switch
            {
                "High" => "failure",
                "Medium" => "neutral",
                _ => "success"
            };

            var summary = $"Risk: {report.RiskLevel} ({report.RiskScore}/100)\n"
                          + $"- Files analyzed: {files.Count}\n"
                          + $"- Patches included: {files.Count(f => !string.IsNullOrWhiteSpace(f.Patch))}";

            var text = "Reasons:\n-" + string.Join("\n- ", report.Reasons)
                        + "\n\nRecommended tests:\n " + string.Join("\n- ", report.RecommendedTests);

            //// Create dummy check run
            await _checksClient.CreateCheckRunAsync
                (
                    token,
                    owner,
                    repo,
                    headSha,
                    title: "MergeGuard Risk Report",
                    summary: summary,
                    text: conclusion,
                    ct
                );

            return Ok(new { ok = true, message = "Risk check created.", risk = report });

            // Remove later
            //var diff = GetString(root, "diff");

            //if (string.IsNullOrWhiteSpace(diff))
            //{
            //    return Ok(new
            //    {
            //        ok = true,
            //        action,
            //        repo = (owner is null || repo is null) ? null : $"{owner}/{repo}",
            //        prNumber,
            //        headSha,
            //        message = "No 'diff' provided in payload. Real GitHub PR webhooks do not include diffs. Implement PR file fetching next."
            //    });
            //}

            //// Analyze the diff with Ollama and get a risk report
            //var report = await _ollama.AnalyzeAsync(diff, ct);

            //return Ok(new
            //{
            //    ok = true,
            //    eventName,
            //    deliveryId,
            //    action,
            //    repo = (owner is null || repo is null) ? null : $"{owner}/{repo}",
            //    prNumber,
            //    headSha,
            //    risk = report
            //});
        }

        /// <summary>
        /// Helper method to build an AI input
        /// </summary>
        /// <param name="owner"></param>
        /// <param name="repo"></param>
        /// <param name="prNumber"></param>
        /// <param name="headSha"></param>
        /// <param name="files"></param>
        /// <param name="maxChars"></param>
        /// <returns></returns>
        private static string BuildAiInput(
            string owner,
            string repo, 
            int prNumber,
            string headSha,
            IReadOnlyList<GitHubPullRequestClient.PullFile> files,
            int maxChars)
        {
            var sb = new StringBuilder();

            sb.AppendLine($"Repo: {owner}/{repo}");
            sb.AppendLine($"PR: #{prNumber}");
            sb.AppendLine($"HEAD SHA: {headSha}");
            sb.AppendLine();

            // Include filenames first (useful even if patches are missing)
            sb.AppendLine("Changed files:");
            foreach(var f in files)
            {
                sb.AppendLine($"- {f.FileName} ({f.Status}, +{f.Additions}/-{f.Deletions})");
            }
            sb.AppendLine();

            sb.AppendLine("Patches (truncated):");

            foreach (var f in files)
            {
                // Lets focus on c# files first
                if (!f.FileName.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (string.IsNullOrWhiteSpace(f.Patch))
                    continue;

                sb.AppendLine($"--- {f.FileName} ---");
                sb.AppendLine(f.Patch);
                sb.AppendLine();

                if (sb.Length >= maxChars)
                    break;
            }

            // absolute cap
            if (sb.Length > maxChars)
                return sb.ToString(0, maxChars);

            return sb.ToString();
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

            return current.ValueKind == JsonValueKind.String ? current.GetString() : current.ToString();
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

        private static long? GetLong(JsonElement root, params string[] path)
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

            return current.ValueKind == JsonValueKind.Number && current.TryGetInt64(out var v) ? v : null;
        }
    }
}
