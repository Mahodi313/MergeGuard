using System.Net.Http.Headers;
using System.Text.Json;

namespace MergeGuard.Services
{
    public sealed class GitHubInstallationTokenClient
    {
        private readonly HttpClient _httpClient;
        private readonly GitHubAppJwtFactory _jwtFactory;
        public GitHubInstallationTokenClient(HttpClient httpClient, GitHubAppJwtFactory jwtFactory)
        {
            _httpClient = httpClient;
            _jwtFactory = jwtFactory;
        }

        public async Task<string> CreateInstallationTokenAsync(long installationId, CancellationToken ct) 
        {
            var jwt = _jwtFactory.CreateJwt();

            using var req = new HttpRequestMessage(HttpMethod.Post, $"app/installations/{installationId}/access_tokens");

            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
            req.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            req.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");

            using var resp = await _httpClient.SendAsync(req, ct);
            resp.EnsureSuccessStatusCode();

            var json = await resp.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);

            return doc.RootElement.GetProperty("token").GetString()
                    ?? throw new InvalidOperationException("Installation token missing from response.");
        }
    }
}
