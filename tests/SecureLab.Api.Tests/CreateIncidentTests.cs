using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class CreateIncidentTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static string UniqueTitle() => "Auth-" + Guid.NewGuid().ToString("N")[..10];

    private static object ValidBody(string title) => new
    {
        title,
        description = "Штучний запис для перевірки створення.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddDays(-1)
    };

    private async Task<Guid> OwnerOf(Guid incidentId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking()
            .SingleAsync(item => item.Id == incidentId);
        return incident.OwnerUserId;
    }

    private static async Task<Guid> CreatedId(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    [Fact] // A-01 на справжньому захищеному create
    public async Task Create_Anonymous_Returns401_NotRedirect()
    {
        using var client = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var response = await client.PostAsJsonAsync("/api/incidents", ValidBody(UniqueTitle()));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
    }

    [Fact] // A-04
    public async Task Create_WithoutOwnerInBody_OwnerIsLoggedInUser()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);

        using var response = await bob.PostAsJsonAsync("/api/incidents", ValidBody(UniqueTitle()));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(DbSeeder.BobId, await OwnerOf(await CreatedId(response)));
    }

    [Fact] // A-05
    public async Task Create_WithForgedOwnerUserId_OwnerStaysPrincipal()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);

        using var response = await bob.PostAsJsonAsync("/api/incidents", new
        {
            title = UniqueTitle(),
            description = "Штучний запис для перевірки створення.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddDays(-1),
            ownerUserId = DbSeeder.AliceId
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var owner = await OwnerOf(await CreatedId(response));
        Assert.Equal(DbSeeder.BobId, owner);
        Assert.NotEqual(DbSeeder.AliceId, owner);
    }
}