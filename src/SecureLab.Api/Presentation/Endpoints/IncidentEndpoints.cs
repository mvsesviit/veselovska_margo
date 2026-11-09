
using System.Security.Claims;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>(
                StatusCodes.Status200OK);

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        endpoints.MapGet(
        "/api/incident-comments/{id:guid}",
        GetCommentAsync)
    .WithTags("Incident Comments")
    .WithName("GetIncidentComment")
    .RequireAuthorization()
    .Produces<IncidentCommentResponse>()
    .ProducesProblem(StatusCodes.Status404NotFound);
        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;

        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(
                    status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(
                    new Dictionary<string, string[]>
                    {
                        ["status"] =
                        [
                            "Allowed values: New, Triaged, InProgress, Resolved, Closed."
                        ]
                    });
            }

            parsedStatus = candidate;
        }

        if (!TryGetReadScope(
                httpContext,
                out var ownerUserId,
                out _))
        {
            return Results.Unauthorized();
        }

        var incidents = await queries.GetListAsync(
            parsedStatus,
            ownerUserId,
            cancellationToken);

        return Results.Ok(incidents);
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!TryGetReadScope(
                httpContext,
                out var ownerUserId,
                out var includeInternalComments))
        {
            return Results.Unauthorized();
        }

        var incident = await queries.GetDetailsAsync(
            id,
            ownerUserId,
            includeInternalComments,
            cancellationToken);

        return incident is null
            ? Results.Problem(
                title: "Incident not found",
                detail: "Incident does not exist or is unavailable.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(incident);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!TryGetReadScope(
                httpContext,
                out var ownerUserId,
                out _))
        {
            return Results.Unauthorized();
        }

        var summary = await queries.GetSeveritySummaryAsync(
            ownerUserId,
            cancellationToken);

        return Results.Ok(summary);
    }

private static async Task<IResult> GetCommentAsync(
    Guid id,
    HttpContext httpContext,
    IncidentQueries queries,
    CancellationToken cancellationToken)
{
    if (!TryGetReadScope(
            httpContext,
            out var ownerUserId,
            out var includeInternalComments))
    {
        return Results.Forbid();
    }

    var comment = await queries.GetCommentAsync(
        id,
        ownerUserId,
        includeInternalComments,
        cancellationToken);

    return comment is null
        ? Results.Problem(
            title: "Comment not found",
            detail: "Comment does not exist or is unavailable.",
            statusCode: StatusCodes.Status404NotFound)
        : Results.Ok(comment);
}
private static async Task<IResult> TriageAsync(
    Guid id,
    HttpContext httpContext,
    IncidentTriageService triageService,
    ILogger<IncidentTriageService> logger,
    CancellationToken cancellationToken)
{
    // Р”РѕР·РІРѕР»СЏС”РјРѕ РѕРїРµСЂР°С†С–СЋ Р»РёС€Рµ Analyst С‚Р° Administrator.
    var isAllowed =
        httpContext.User.IsInRole("Analyst")
        || httpContext.User.IsInRole("Administrator");

    if (!isAllowed)
{
    var deniedUserId = httpContext.User.FindFirst(
        ClaimTypes.NameIdentifier)?.Value ?? "unknown";

    logger.LogWarning(
        "Denied incident triage. UserId: {UserId}, IncidentId: {IncidentId}",
        deniedUserId,
        id);

    return Results.Forbid();
}

    // Р†РґРµРЅС‚РёС„С–РєР°С‚РѕСЂ РІРёРєРѕРЅР°РІС†СЏ Р±РµСЂРµРјРѕ Р»РёС€Рµ Р· РїРµСЂРµРІС–СЂРµРЅРёС… claims.
    var idValue = httpContext.User.FindFirst(
        ClaimTypes.NameIdentifier)?.Value;

    if (!Guid.TryParse(idValue, out var changedByUserId))
    {
        return Results.Forbid();
    }

    var result = await triageService.TriageAsync(
        id,
        changedByUserId,
        cancellationToken);

    return result switch
    {
        IncidentTriageResult.Success => Results.NoContent(),

        IncidentTriageResult.NotFound => Results.Problem(
            title: "Incident not found",
            statusCode: StatusCodes.Status404NotFound),

        IncidentTriageResult.InvalidStatus => Results.Problem(
            title: "Invalid status transition",
            detail: "Only incidents with status New can be triaged.",
            statusCode: StatusCodes.Status409Conflict),

        _ => Results.Problem(
            title: "Unexpected error",
            statusCode: StatusCodes.Status500InternalServerError)
    };
}
    private static bool TryGetReadScope(
        HttpContext context,
        out Guid? ownerUserId,
        out bool includeInternalComments)
    {
        ownerUserId = null;
        includeInternalComments = false;

        var idValue = context.User.FindFirst(
            ClaimTypes.NameIdentifier)?.Value;

        if (!Guid.TryParse(idValue, out var verifiedUserId))
        {
            return false;
        }

        var isReporter = context.User.IsInRole("Reporter");
        var isAnalyst = context.User.IsInRole("Analyst");
        var isAdministrator = context.User.IsInRole("Administrator");

        // РќРµ РЅР°РґР°С”РјРѕ РґРѕСЃС‚СѓРї РєРѕСЂРёСЃС‚СѓРІР°С‡Р°Рј С–Р· РЅРµРІС–РґРѕРјРёРјРё СЂРѕР»СЏРјРё.
        if (!isReporter && !isAnalyst && !isAdministrator)
        {
            return false;
        }

        // Reporter РѕР±РјРµР¶РµРЅРёР№ РІР»Р°СЃРЅРёРјРё Р·Р°РїРёСЃР°РјРё.
        // Analyst С‚Р° Administrator РјРѕР¶СѓС‚СЊ С‡РёС‚Р°С‚Рё РІСЃС– С–РЅС†РёРґРµРЅС‚Рё.
        if (!isAnalyst && !isAdministrator)
        {
            ownerUserId = verifiedUserId;
        }

        // Р’РЅСѓС‚СЂС–С€РЅС– РєРѕРјРµРЅС‚Р°СЂС– РґРѕСЃС‚СѓРїРЅС– Р»РёС€Рµ Analyst.
        includeInternalComments = isAnalyst || isAdministrator;

        return true;
    }
}
