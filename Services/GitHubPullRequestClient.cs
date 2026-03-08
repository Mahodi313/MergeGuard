using System.Net.Http.Headers;
using System.Text.Json;

namespace MergeGuard.Services
{
    public sealed class GitHubPullRequestClient
    {
        private readonly HttpClient _httpClient;

        public GitHubPullRequestClient(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public sealed record PullFile(string FileName, string? Status, int? Additions, int? Deletions, int? Changes, string? Patch);

        /// <summary>
        /// Uses the installation token to call Github REST API
        /// Patch is not guaranteed for every file (normal), binary files, large diffs, etc.222
        /// </summary>
        /// <param name="installationToken"></param>
        /// <param name="owner"></param>
        /// <param name="repo"></param>
        /// <param name="pullNumber"></param>
        /// <param name="ct"></param>
        /// <returns>Returns the list of PR files and their patch snippets when availe</returns>
        public async Task<IReadOnlyList<PullFile>> ListPullRequestFilesAsync(
            string installationToken,
            string owner,
            string repo,
            int pullNumber,
            CancellationToken ct)
        {
            // GitHub REST: GET /repos/{owner}/{repo}/pulls/{pull_number}/files
            using var req = new HttpRequestMessage(
                HttpMethod.Get,
                $"repos/{owner}/{repo}/pulls/{pullNumber}/files?per_page=100"
            );

            req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", installationToken);
            req.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

            using var resp = await _httpClient.SendAsync(req, ct);
            resp.EnsureSuccessStatusCode();

            var json = await resp.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);

            var list = new List<PullFile>();

            foreach(var item in doc.RootElement.EnumerateArray())
            {
                var fileName = item.GetProperty("filename").GetString() ?? "(unknown)";
                var status = item.TryGetProperty("status", out var s) ? s.GetString() : null;

                int? additions = item.TryGetProperty("additions", out var a) && a.TryGetInt32(out var add) ? add : null;
                int? deletions = item.TryGetProperty("deletions", out var d) && d.TryGetInt32(out var del) ? del : null;
                int? changes = item.TryGetProperty("changes", out var c) && c.TryGetInt32(out var ci) ? ci : null;

                var patch = item.TryGetProperty("patch", out var p) ? p.GetString() : null;

                list.Add(new PullFile(fileName, status, additions, deletions, changes, patch));
            }

            return list;
        }
    }
}
