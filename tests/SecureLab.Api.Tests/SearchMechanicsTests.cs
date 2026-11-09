
using System.Net;
using SecureLab.Api.Tests;

namespace SecureLab.Api.Tests;

public sealed class SearchMechanicsTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException(
            "Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task Search_ReturnsJson()
    {
        using var client = await factory.LoginAsync("morgan", StudyPassword);

        using var response = await client.GetAsync(
            "/api/incidents/search?q=РЅР°РІС‡Р°Р»СЊРЅ");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
            "application/json",
            response.Content.Headers.ContentType?.MediaType);
    }
}
