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
    private readonly HttpClient _client = factory.CreateClient();

    // T-02: некоректний DTO -> 400 з ключем severity
    [Fact]
    public async Task Post_WithInvalidSeverity_Returns400WithSeverityKey()
    {
        var body = new
        {
            title = $"T02-{Guid.NewGuid():N}",
            description = "Штучний запис для перевірки.",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        using var response = await _client.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json",
            response.Content.Headers.ContentType?.MediaType);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("errors")
            .TryGetProperty("severity", out _));
        Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
    }

    // T-03: повторний активний title -> 409
    [Fact]
    public async Task Post_WithDuplicateActiveTitle_Returns409()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Штучний запис для перевірки конфлікту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        try
        {
            using var first = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            using var second = await _client.PostAsJsonAsync("/api/incidents", body);
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

    // S-02 (відмінний рівень): контрольний ввід -> порожня множина,
    // а звичайний пошук USB -> рівно один запис
    [Fact]
    public async Task Search_ControlInput_ReturnsExactEmptySet_AndUsbIsStillFound()
    {
        var control = "zz-no-match' OR TRUE -- ";
        var found = await _client.GetFromJsonAsync<List<CreatedIncidentResponse>>(
            "/api/incidents/search?q=" + Uri.EscapeDataString(control));
        Assert.NotNull(found);
        Assert.Empty(found);

        var usb = await _client.GetFromJsonAsync<List<CreatedIncidentResponse>>(
            "/api/incidents/search?q=USB");
        Assert.NotNull(usb);
        var only = Assert.Single(usb);
        Assert.Equal(Guid.Parse("20000000-0000-0000-0000-000000000005"), only.Id);
    }

    // T-04: легітимний апостроф
    [Fact]
    public async Task Search_Apostrophe_ReturnsOnlyObrienRecord()
    {
        var found = await _client.GetFromJsonAsync<List<CreatedIncidentResponse>>(
            "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien"));
        Assert.NotNull(found);
        var only = Assert.Single(found);
        Assert.Equal(Guid.Parse("20000000-0000-0000-0000-000000000004"), only.Id);
    }

    // A-02: зайві server-managed поля ігноруються (overposting)
    [Fact]
    public async Task Post_WithServerManagedFields_IgnoresThem()
    {
        var sentId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var title = $"Overpost-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Штучний запис для перевірки overposting.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
            id = sentId,
            ownerUserId = Guid.NewGuid(),
            status = "Closed",
            createdAtUtc = "2000-01-01T00:00:00Z"
        };

        try
        {
            using var response = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var created = await response.Content
                .ReadFromJsonAsync<CreatedIncidentResponse>();
            Assert.NotNull(created);
            Assert.NotEqual(sentId, created.Id);
            Assert.Equal("New", created.Status);
            Assert.True(created.CreatedAtUtc > DateTimeOffset.UtcNow.AddDays(-1));

            using var detail = await _client.GetAsync($"/api/incidents/{created.Id}");
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
}