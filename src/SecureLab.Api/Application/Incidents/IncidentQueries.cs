
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(
    SecureLabDbContext dbContext,
    ILogger<IncidentQueries> logger)
{
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        Guid? ownerUserId,
        CancellationToken cancellationToken)
    {
        logger.LogInformation(
            "Loading incidents with status filter {Status} and owner {OwnerUserId}",
            status,
            ownerUserId);

        var query = dbContext.Incidents.AsNoTracking();

        if (ownerUserId.HasValue)
        {
            query = query.Where(incident => incident.OwnerUserId == ownerUserId.Value);
        }

        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    public Task<IncidentDetailsResponse?> GetDetailsAsync(
        Guid id,
        Guid? ownerUserId,
        bool includeInternalComments,
        CancellationToken cancellationToken)
    {
        logger.LogInformation(
            "Loading incident {IncidentId} for owner {OwnerUserId}",
            id,
            ownerUserId);

        var query = dbContext.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == id);

        if (ownerUserId.HasValue)
        {
            query = query.Where(incident => incident.OwnerUserId == ownerUserId.Value);
        }

        return query
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => includeInternalComments || !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);}
            public Task<IncidentCommentResponse?> GetCommentAsync(
    Guid id,
    Guid? ownerUserId,
    bool includeInternalComments,
    CancellationToken cancellationToken)
{
    var query = dbContext.IncidentComments
        .AsNoTracking()
        .Where(comment => comment.Id == id);

    // Перевіряємо власника батьківського інциденту.
    if (ownerUserId.HasValue)
    {
        query = query.Where(
            comment => comment.Incident.OwnerUserId == ownerUserId.Value);
    }

    // Внутрішні коментарі доступні лише дозволеним ролям.
    if (!includeInternalComments)
    {
        query = query.Where(comment => !comment.IsInternal);
    }

    return query
        .Select(comment => new IncidentCommentResponse(
            comment.Id,
            comment.Author.DisplayName,
            comment.Text,
            comment.CreatedAtUtc))
        .SingleOrDefaultAsync(cancellationToken);

    }

    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(
        Guid? ownerUserId,
        CancellationToken cancellationToken)
    {
        logger.LogInformation(
            "Loading incident severity summary for owner {OwnerUserId}",
            ownerUserId);

        var query = dbContext.Incidents.AsNoTracking();

        if (ownerUserId.HasValue)
        {
            query = query.Where(incident => incident.OwnerUserId == ownerUserId.Value);
        }

        var result = await query
            .GroupBy(incident => incident.Severity)
            .Select(group => new IncidentSeveritySummaryResponse(
                group.Key.ToString(),
                group.Count()))
            .ToListAsync(cancellationToken);

        return result
            .OrderBy(item => item.Severity, StringComparer.Ordinal)
            .ToList();
    }
}