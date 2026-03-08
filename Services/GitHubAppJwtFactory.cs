using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace MergeGuard.Services
{
    public sealed class GitHubAppJwtFactory
    {
        private readonly IConfiguration _config;

        public GitHubAppJwtFactory(IConfiguration config)
        {
            _config = config;
        }

        public string CreateJwt()
        {
            // Github app id is used as the "iis"
            var appIdRaw = _config["GitHub:AppId"];
            if (string.IsNullOrWhiteSpace(appIdRaw))
            {
                throw new InvalidOperationException("Missing GitHub:AppId in configuration.");
            }

            var keyPath = _config["GitHub:PrivateKeyPath"];
            if (string.IsNullOrWhiteSpace(keyPath))
            {
                throw new InvalidOperationException("Missing GitHub:PrivateKeyPath in configuration.");
            }

            var pem = File.ReadAllText(keyPath);

            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);

            var now = DateTimeOffset.UtcNow;
            var stringtest = "test";

            //Github requries:
            // "iat" - Issued at (now)
            // "exp"- short expiration, max 10 minutes from now
            // "iss" - GitHub App's identifier

            // Note: System.IdentityModel.Tokens.Jwt does not support "nbf" claim, and GitHub does not require it, so we omit it.

            var claims = new List<Claim>
            {
                new ("iat", now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new("exp", now.AddMinutes(9).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new("iss", appIdRaw)
            };

            var creds = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

            var token = new JwtSecurityToken(
                claims: claims,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
