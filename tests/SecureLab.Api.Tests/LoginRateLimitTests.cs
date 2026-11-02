using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public sealed class LoginRateLimitTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static Task<HttpResponseMessage> Login(HttpClient client, string user, string password)
        => client.PostAsJsonAsync("/api/auth/login", new { userName = user, password });

    [Fact]
    public async Task Login_TooManyAttempts_Returns429_AndRecoversAfterWindow()
    {
        // Окремий host = окремі лічильники. Інші тести цього не зачіпають.
        using var host = factory.WithWebHostBuilder(_ => { });
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        // 10 невдалих спроб дозволено: звичайна відмова 401.
        for (var i = 0; i < 10; i++)
        {
            using var attempt = await Login(client, "nobody" + i, StudyPassword + "x");
            Assert.Equal(HttpStatusCode.Unauthorized, attempt.StatusCode);
        }

        // Далі 429 і для невідомого імені, і для реального: існування акаунта не розкривається.
        using var unknown = await Login(client, "nobody-extra", "wrong");
        using var known = await Login(client, "alice", "wrong");
        Assert.Equal(HttpStatusCode.TooManyRequests, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, known.StatusCode);

        // Після завершення вікна вхід знову працює.
        await Task.Delay(TimeSpan.FromSeconds(11));
        using var recovered = await Login(client, "alice", StudyPassword);
        Assert.Equal(HttpStatusCode.NoContent, recovered.StatusCode);
    }
}