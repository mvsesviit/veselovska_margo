using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public sealed class RegisterTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static string NewName() => "reg" + Guid.NewGuid().ToString("N")[..8];

    private HttpClient NewClient() => factory.CreateClient(
        new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private static object Body(string userName, string? displayName = "Тестовий користувач",
        string? password = null) => new
    {
        userName,
        email = userName + "@example.test",
        displayName,
        password = password ?? StudyPassword
    };

    [Fact] // T-01
    public async Task Register_Valid_Returns201_WithoutSensitiveFields()
    {
        using var client = NewClient();
        using var response = await client.PostAsJsonAsync("/api/auth/register", Body(NewName()));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("id", out _));
        Assert.False(root.TryGetProperty("password", out _));
        Assert.False(root.TryGetProperty("passwordHash", out _));
        Assert.False(root.TryGetProperty("securityStamp", out _));
    }

    [Fact] // T-02
    public async Task Register_WeakPassword_Returns400()
    {
        using var client = NewClient();
        using var response = await client.PostAsJsonAsync("/api/auth/register",
            Body(NewName(), password: "short"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact] // duplicate-контракт (добрий рівень)
    public async Task Register_Duplicate_Returns409()
    {
        using var client = NewClient();
        var name = NewName();

        using var first = await client.PostAsJsonAsync("/api/auth/register", Body(name));
        using var second = await client.PostAsJsonAsync("/api/auth/register", Body(name));

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact] // межа довжини displayName (добрий рівень)
    public async Task Register_DisplayName121_Returns400()
    {
        using var client = NewClient();
        using var response = await client.PostAsJsonAsync("/api/auth/register",
            Body(NewName(), displayName: new string('a', 121)));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}