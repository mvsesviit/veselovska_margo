using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private HttpClient Anonymous() => factory.CreateClient(
        new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private static async Task<JsonElement> ReadJson(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }

    [Fact] // A-01
    public async Task Me_Anonymous_Returns401_NotRedirect()
    {
        using var client = Anonymous();
        using var response = await client.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
    }

    [Fact] // A-02
    public async Task Login_ThenMe_ReturnsCurrentUser_WithSafeFieldsOnly()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJson(response);
        Assert.Equal(DbSeeder.AliceId, json.GetProperty("id").GetGuid());
        Assert.Equal("alice", json.GetProperty("userName").GetString());
        Assert.False(json.TryGetProperty("passwordHash", out _));
        Assert.False(json.TryGetProperty("securityStamp", out _));
        Assert.False(json.TryGetProperty("email", out _));
    }

    [Fact] // A-03
    public async Task Me_ForgedDemoHeader_DoesNotChangeCurrentUser()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await alice.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJson(response);
        Assert.Equal(DbSeeder.AliceId, json.GetProperty("id").GetGuid());
    }

    [Fact] // A-03 (варіант без cookie): header сам нічого не доводить
    public async Task Me_DemoHeaderWithoutCookie_Returns401()
    {
        using var client = Anonymous();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact] // A-06
    public async Task Logout_ThenMe_Returns401()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var before = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        using var logout = await alice.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        using var after = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact] // A-07
    public async Task Login_UnknownUser_And_WrongPassword_LookIdenticalOutside()
    {
        using var client1 = Anonymous();
        using var client2 = Anonymous();

        using var unknown = await client1.PostAsJsonAsync("/api/auth/login",
            new { userName = "nobody" + Guid.NewGuid().ToString("N")[..8], password = StudyPassword });
        using var wrong = await client2.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = StudyPassword + "x" });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(unknown.StatusCode, wrong.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.MediaType,
                     wrong.Content.Headers.ContentType?.MediaType);
        Assert.Equal(await StableShape(unknown), await StableShape(wrong));
    }

    // traceId відрізняється в кожному запиті, тому порівнюємо лише стабільні поля.
    private static async Task<string> StableShape(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(body)) return "<empty>";
        try
        {
            using var doc = JsonDocument.Parse(body);
            string Get(string name) =>
                doc.RootElement.TryGetProperty(name, out var p) ? p.ToString() : "<none>";
            return $"{Get("type")}|{Get("title")}|{Get("status")}|{Get("detail")}";
        }
        catch (JsonException)
        {
            return body;
        }
    }
}