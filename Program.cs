using MergeGuard.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddHttpClient<OllamaRiskClient>(client =>
{
    client.BaseAddress = new Uri(
        builder.Configuration["Ollama:BaseUrl"] ?? "http://localhost:11434/api/"
    );
});

builder.Services.AddSingleton<GitHubAppJwtFactory>();

// Creates typed clients for github api calls.
// Sets a user agent (Github requires a user agent header for api requests)
builder.Services.AddHttpClient<GitHubInstallationTokenClient>(c =>
{
    c.BaseAddress = new Uri("https://api.github.com/");
    c.DefaultRequestHeaders.UserAgent.ParseAdd("MergeGuard-App");
});

builder.Services.AddHttpClient<GitHubChecksClient>(c =>
{
    c.BaseAddress = new Uri("https://api.github.com/");
    c.DefaultRequestHeaders.UserAgent.ParseAdd("MergeGuard-App");
});

builder.Services.AddHttpClient<GitHubPullRequestClient>(c =>
{
    c.BaseAddress = new Uri("https://api.github.com/");
    c.DefaultRequestHeaders.UserAgent.ParseAdd("MergeGuard-App");
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Todo: Enable later after testing with ngrok.
//app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
