using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public sealed class CookieFlagsTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private const string CookieName = ".AspNetCore.Identity.Application=";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Повертає лише атрибути cookie (без її значення), у нижньому регістрі.
    private async Task<string[]> LoginAndReadAttributes(string baseAddress)
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
            AllowAutoRedirect = false
        });

        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var matching = response.Headers.GetValues("Set-Cookie")
            .Where(value => value.StartsWith(CookieName)).ToArray();
        // Перевірка за кількістю: значення cookie не потрапить у повідомлення про помилку.
        Assert.True(matching.Length == 1);

        // Перша частина «назва=значення» пропускається, її не читаємо й не друкуємо.
        return matching[0].Split(';').Skip(1)
            .Select(part => part.Trim().ToLowerInvariant()).ToArray();
    }

    [Fact]
    public async Task Login_OverHttps_CookieIsHttpOnly_SameSiteLax_Secure()
    {
        var attributes = await LoginAndReadAttributes("https://localhost");

        Assert.Contains("httponly", attributes);
        Assert.Contains("samesite=lax", attributes);
        Assert.Contains("secure", attributes);
        Assert.Contains("path=/", attributes);
    }

    [Fact]
    public async Task Login_OverHttp_InDevelopment_CookieIsNotSecure_ButStillHttpOnly()
    {
        var attributes = await LoginAndReadAttributes("http://localhost");

        Assert.Contains("httponly", attributes);
        Assert.Contains("samesite=lax", attributes);
        Assert.DoesNotContain("secure", attributes);
    }
}