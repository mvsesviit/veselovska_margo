using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class Lab02ContractTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{


    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // T-02: РЅРµРєРѕСЂРµРєС‚РЅРёР№ DTO -> 400 Р· РєР»СЋС‡РµРј severity
    [Fact]
    public async Task Post_WithInvalidSeverity_Returns400WithSeverityKey()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        var body = new
        {
            title = $"T02-{Guid.NewGuid():N}",
            description = "РЁС‚СѓС‡РЅРёР№ Р·Р°РїРёСЃ РґР»СЏ РїРµСЂРµРІС–СЂРєРё.",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        using var response = await client.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json",
            response.Content.Headers.ContentType?.MediaType);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("errors")
            .TryGetProperty("severity", out _));
        Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
    }

    // T-03: РїРѕРІС‚РѕСЂРЅРёР№ Р°РєС‚РёРІРЅРёР№ title -> 409
    [Fact]
    public async Task Post_WithDuplicateActiveTitle_Returns409()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        var title = $"Regression-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "РЁС‚СѓС‡РЅРёР№ Р·Р°РїРёСЃ РґР»СЏ РїРµСЂРµРІС–СЂРєРё РєРѕРЅС„Р»С–РєС‚Сѓ.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        try
        {
            using var first = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            using var second = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
            Assert.Equal("application/problem+json",
                second.Content.Headers.ContentType?.MediaType);
            var json = await second.Content.ReadAsStringAsync();
            Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
        }
        finally
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
        }
    }

    // S-02 (РІС–РґРјС–РЅРЅРёР№ СЂС–РІРµРЅСЊ): РєРѕРЅС‚СЂРѕР»СЊРЅРёР№ РІРІС–Рґ -> РїРѕСЂРѕР¶РЅСЏ РјРЅРѕР¶РёРЅР°,
    // Р° Р·РІРёС‡Р°Р№РЅРёР№ РїРѕС€СѓРє USB -> СЂС–РІРЅРѕ РѕРґРёРЅ Р·Р°РїРёСЃ
    [Fact]
    public async Task Search_ControlInput_ReturnsExactEmptySet_AndUsbIsStillFound()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        var control = "zz-no-match' OR TRUE -- ";
        var found = await client.GetFromJsonAsync<List<CreatedIncidentResponse>>(
            "/api/incidents/search?q=" + Uri.EscapeDataString(control));
        Assert.NotNull(found);
        Assert.Empty(found);

        var usb = await client.GetFromJsonAsync<List<CreatedIncidentResponse>>(
            "/api/incidents/search?q=USB");
        Assert.NotNull(usb);
        var only = Assert.Single(usb);
        Assert.Equal(Guid.Parse("20000000-0000-0000-0000-000000000005"), only.Id);
    }

    // T-04: Р»РµРіС–С‚РёРјРЅРёР№ Р°РїРѕСЃС‚СЂРѕС„
    [Fact]
   public async Task Search_Apostrophe_ReturnsOnlyObrienRecord()
{
    using var client = await factory.LoginAsync("morgan", StudyPassword);
        var found = await client.GetFromJsonAsync<List<CreatedIncidentResponse>>(
            "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien"));
        Assert.NotNull(found);
        var only = Assert.Single(found);
        Assert.Equal(Guid.Parse("20000000-0000-0000-0000-000000000004"), only.Id);
    }

    // Р›Р  2: Р·Р°Р№РІС– server-managed РїРѕР»СЏ С–РіРЅРѕСЂСѓСЋС‚СЊСЃСЏ (overposting)
    [Fact]
    public async Task Post_WithServerManagedFields_IgnoresThem()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        var sentId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var title = $"Overpost-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "РЁС‚СѓС‡РЅРёР№ Р·Р°РїРёСЃ РґР»СЏ РїРµСЂРµРІС–СЂРєРё overposting.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
            id = sentId,
            ownerUserId = Guid.NewGuid(),
            status = "Closed",
            createdAtUtc = "2000-01-01T00:00:00Z"
        };

        try
        {
            using var response = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var created = await response.Content
                .ReadFromJsonAsync<CreatedIncidentResponse>();
            Assert.NotNull(created);
            Assert.NotEqual(sentId, created.Id);
            Assert.Equal("New", created.Status);
            Assert.True(created.CreatedAtUtc > DateTimeOffset.UtcNow.AddDays(-1));

            using var detail = await client.GetAsync($"/api/incidents/{created.Id}");
            Assert.Equal(HttpStatusCode.OK, detail.StatusCode);
            using var doc = JsonDocument.Parse(await detail.Content.ReadAsStringAsync());
            Assert.Equal("Аліса Коваль",
    doc.RootElement.GetProperty("ownerDisplayName").GetString());
        }
        finally
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
        }
    }
    [Fact]
public async Task Search_ResultsAreScopedByRole()
{
    const string bobIncidentId =
        "20000000-0000-0000-0000-000000000002";

    using var aliceClient = await factory.LoginAsync(
        "alice", StudyPassword);

    var aliceResults =
        await aliceClient.GetFromJsonAsync<List<CreatedIncidentResponse>>(
            "/api/incidents/search?q=" +
            Uri.EscapeDataString(""));

    Assert.NotNull(aliceResults);
    Assert.DoesNotContain(
        aliceResults,
        item => item.Id.ToString() == bobIncidentId);

    using var morganClient = await factory.LoginAsync(
        "morgan", StudyPassword);

    var analystResults =
        await morganClient.GetFromJsonAsync<List<CreatedIncidentResponse>>(
            "/api/incidents/search?q=" +
            Uri.EscapeDataString(""));

    Assert.NotNull(analystResults);
    Assert.Contains(
        analystResults,
        item => item.Id.ToString() == bobIncidentId);
}

[Fact]
public async Task SeveritySummary_IsScopedByRole()
{
    using var aliceClient = await factory.LoginAsync(
        "alice", StudyPassword);

    var aliceSummary =
        await aliceClient.GetFromJsonAsync<
            List<System.Text.Json.JsonElement>>(
                "/api/incidents/severity-summary");

    Assert.NotNull(aliceSummary);

    var aliceCount = aliceSummary.Sum(
        item => item.GetProperty("count").GetInt32());

    Assert.True(aliceCount > 0);

    using var morganClient = await factory.LoginAsync(
        "morgan", StudyPassword);

    var analystSummary =
        await morganClient.GetFromJsonAsync<
            List<System.Text.Json.JsonElement>>(
                "/api/incidents/severity-summary");

    Assert.NotNull(analystSummary);

    var analystCount = analystSummary.Sum(
        item => item.GetProperty("count").GetInt32());

    Assert.True(analystCount > aliceCount);
}

}
