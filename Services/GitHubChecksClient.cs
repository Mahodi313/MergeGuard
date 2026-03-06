using System.Net.Http.Headers;

namespace MergeGuard.Services
{
    public sealed class GitHubChecksClient
    {
        private readonly HttpClient _httpClient;

        public GitHubChecksClient(HttpClient httpClient)
        {
            _httpClient = httpClient;         
        }

        public async Task CreateCheckRunAsync
        (
            string installationToken, 
            string owner, 
            string repo, 
            string headSha, 
            string title,
            string summary,
            string text,
            string conclusion,
            CancellationToken ct)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, $"repos/{owner}/{repo}/check-runs");

            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", installationToken);
            req.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

            var body = new
            {
                name = "MergeGuard",
                head_sha = headSha,
                status = "completed",
                conclusion = conclusion, // "success", "neutral", "failure" etc.
                output = new
                {
                    title,
                    summary,
                    text
                }
            };

            req.Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json");

            using var resp = await _httpClient.SendAsync(req, ct);
            resp.EnsureSuccessStatusCode();
        }
    }
}
