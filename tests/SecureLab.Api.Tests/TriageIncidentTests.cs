using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class TriageIncidentTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException(
            "Set local SeedUsers__Password outside Git.");

    private static object ValidBody() => new
    {
        title = "Triage-" + Guid.NewGuid().ToString("N")[..10],
        description = "Штучний запис для перевірки переходу статусу.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddDays(-1)
    };

    private async Task<Guid> CreateIncidentAsync()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        using var response = await client.PostAsJsonAsync(
            "/api/incidents",
            ValidBody());

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        using var document = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync());

        return document.RootElement.GetProperty("id").GetGuid();
    }

    private async Task<(IncidentStatus Status, int HistoryCount)> ReadStateAsync(
        Guid incidentId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();

        var incident = await db.Incidents
            .AsNoTracking()
            .SingleAsync(item => item.Id == incidentId);

        var historyCount = await db.IncidentStatusHistory
            .CountAsync(item => item.IncidentId == incidentId);

        return (incident.Status, historyCount);
    }

    [Fact]
    public async Task Reporter_CannotTriage_AndDatabaseRemainsUnchanged()
    {
        var incidentId = await CreateIncidentAsync();
        var before = await ReadStateAsync(incidentId);

        using var reporter = await factory.LoginAsync("alice", StudyPassword);

        using var response = await reporter.PostAsync(
            $"/api/incidents/{incidentId}/triage",
            content: null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        var after = await ReadStateAsync(incidentId);

        Assert.Equal(IncidentStatus.New, after.Status);
        Assert.Equal(before.HistoryCount, after.HistoryCount);
    }

    [Fact]
    public async Task Analyst_CanTriageNewIncident_AndCannotRepeatTransition()
    {
        var incidentId = await CreateIncidentAsync();

        using var analyst = await factory.LoginAsync("morgan", StudyPassword);

        using var response = await analyst.PostAsync(
            $"/api/incidents/{incidentId}/triage",
            content: null);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var afterTriage = await ReadStateAsync(incidentId);

        Assert.Equal(IncidentStatus.Triaged, afterTriage.Status);
        Assert.Equal(1, afterTriage.HistoryCount);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();

        var history = await db.IncidentStatusHistory
            .AsNoTracking()
            .SingleAsync(item => item.IncidentId == incidentId);

        Assert.Equal(IncidentStatus.New, history.OldStatus);
        Assert.Equal(IncidentStatus.Triaged, history.NewStatus);
        Assert.Equal(DbSeeder.MorganId, history.ChangedByUserId);

        using var repeatedResponse = await analyst.PostAsync(
            $"/api/incidents/{incidentId}/triage",
            content: null);

        Assert.Equal(HttpStatusCode.Conflict, repeatedResponse.StatusCode);

        var afterRepeatedAttempt = await ReadStateAsync(incidentId);

        Assert.Equal(IncidentStatus.Triaged, afterRepeatedAttempt.Status);
        Assert.Equal(1, afterRepeatedAttempt.HistoryCount);
    }
}
