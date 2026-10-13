using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace SecureLab.Api.Scaffolding;

public static class Lab02Endpoints
{
    // Метод для екранування спеціальних символів SQL
    static string EscapeLike(string value) => value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");

    public static void MapLab02Endpoints(this WebApplication app)
    {
        // =========================================================
        // 1. ВИПРАВЛЕНИЙ ПОШУК (GET /api/incidents/search)
        // =========================================================
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            var pattern = "%" + EscapeLike(q ?? "") + "%";

            // LINQ замість вразливого FromSqlRaw
            var found = db.Incidents.AsNoTracking()
                .Where(i => EF.Functions.ILike(i.Title, pattern, "\\") || EF.Functions.ILike(i.Description, pattern, "\\"));

            // Безпечне сортування через Allowlist
            IQueryable<Incident>? ordered = sortBy switch
            {
                null or "" or "createdAtUtc" => found.OrderByDescending(i => i.CreatedAtUtc).ThenBy(i => i.Id),
                "severity" => found.OrderBy(i => i.Severity == IncidentSeverity.Critical ? 0 :
                                                 i.Severity == IncidentSeverity.High ? 1 :
                                                 i.Severity == IncidentSeverity.Medium ? 2 : 3).ThenBy(i => i.Id),
                "status" => found.OrderBy(i => i.Status == IncidentStatus.New ? 0 :
                                               i.Status == IncidentStatus.Triaged ? 1 :
                                               i.Status == IncidentStatus.InProgress ? 2 :
                                               i.Status == IncidentStatus.Resolved ? 3 : 4).ThenBy(i => i.Id),
                _ => null
            };

            // Якщо передали неправильне поле для сортування - повертаємо 400
            if (ordered is null)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."] });
            }

            var items = await ordered.Take(50)
                .Select(i => new CreatedIncidentResponse(i.Id, i.Title, i.Severity.ToString(), i.Status.ToString(), i.CreatedAtUtc, i.OccurredAtUtc))
                .ToListAsync(ct);

            return Results.Ok(items);
        });

        // =========================================================
        // 2. СТВОРЕННЯ ІНЦИДЕНТУ З ПЕРЕВІРКАМИ (POST /api/incidents)
        // =========================================================
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
        {
            var errors = new Dictionary<string, string[]>();
            var now = DateTimeOffset.UtcNow;

            // Перевірка Title
            if (string.IsNullOrWhiteSpace(request.Title))
                errors["title"] = ["Title is required."];
            else if (request.Title.Length > 160)
                errors["title"] = ["Title не довше 160 символів."];

            // Перевірка Description
            if (string.IsNullOrWhiteSpace(request.Description))
                errors["description"] = ["Description is required."];
            else if (request.Description.Length > 4000)
                errors["description"] = ["Description не довше 4000 символів."];

            // Перевірка Severity (Enum)
            var severityIsValid = Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity) && Enum.IsDefined(severity);
            if (!severityIsValid)
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

            // Перевірка дати
            if (request.OccurredAtUtc is null)
                errors["occurredAtUtc"] = ["OccurredAtUtc обов'язковий."];
            else if (request.OccurredAtUtc > now.AddMinutes(5))
                errors["occurredAtUtc"] = ["Дата не може бути в майбутньому (більше ніж на 5 хв)."];

            var title = request.Title?.Trim() ?? "";
            var description = request.Description?.Trim() ?? "";

            // Cross-field перевірка (Для оцінки "Добре" - Т-09)
            if (severityIsValid && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
                && !errors.ContainsKey("description") && description.Length < 40)
            {
                errors["description"] = ["Для High або Critical description після Trim() має містити щонайменше 40 символів."];
            }

            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            // Предметний конфлікт дублікатів (Для оцінки "Добре" - Т-03)
            var activeStatuses = new[] { IncidentStatus.New, IncidentStatus.Triaged, IncidentStatus.InProgress, IncidentStatus.Resolved };
            var isDuplicate = await db.Incidents.AnyAsync(i => i.Title == title && activeStatuses.Contains(i.Status), ct);
            if (isDuplicate)
            {
                return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "Конфлікт", detail: "Інцидент з таким заголовком вже існує.");
            }

            // Створення (Entity) - сервер сам додає потрібні службові поля
            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                Title = title,
                Description = description,
                Severity = severity,
                Status = IncidentStatus.New,
                OwnerUserId = DbSeeder.AliceId,
                OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };

            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);

            var response = new CreatedIncidentResponse(incident.Id, incident.Title, incident.Severity.ToString(), incident.Status.ToString(), incident.CreatedAtUtc, incident.OccurredAtUtc);
            return Results.Created($"/api/incidents/{incident.Id}", response);
        });
    }
}

// =========================================================
// 3. КОНТРАКТИ (DTO) - Щоб клієнт не міг передати зайві поля
// =========================================================
public sealed record CreateIncidentRequest(string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);
public sealed record CreatedIncidentResponse(Guid Id, string Title, string Severity, string Status, DateTimeOffset CreatedAtUtc, DateTimeOffset OccurredAtUtc);