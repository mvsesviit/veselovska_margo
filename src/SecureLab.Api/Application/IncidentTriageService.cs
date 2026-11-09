using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

public enum IncidentTriageResult
{
    Success,
    NotFound,
    InvalidStatus
}

public sealed class IncidentTriageService(SecureLabDbContext dbContext)
{
    public async Task<IncidentTriageResult> TriageAsync(
        Guid incidentId,
        Guid changedByUserId,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(
                item => item.Id == incidentId,
                cancellationToken);

        if (incident is null)
        {
            return IncidentTriageResult.NotFound;
        }

        // Дозволений лише перехід New -> Triaged.
        if (incident.Status != IncidentStatus.New)
        {
            return IncidentTriageResult.InvalidStatus;
        }

        var now = DateTimeOffset.UtcNow;

        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;

        dbContext.IncidentStatusHistory.Add(
            new IncidentStatusHistory
            {
                Id = Guid.NewGuid(),
                IncidentId = incident.Id,
                ChangedByUserId = changedByUserId,
                OldStatus = IncidentStatus.New,
                NewStatus = IncidentStatus.Triaged,
                Note = "Incident triaged by an authorized analyst.",
                CreatedAtUtc = now
            });

        await dbContext.SaveChangesAsync(cancellationToken);

        return IncidentTriageResult.Success;
    }
}