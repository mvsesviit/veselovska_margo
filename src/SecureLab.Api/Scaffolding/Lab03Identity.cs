using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();

builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.ValidationInterval = TimeSpan.Zero;
});
        builder.Services.AddAuthorization();

        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy("login", context => IpFixedWindow(context, 10, TimeSpan.FromSeconds(10)));
            options.AddPolicy("register", context => IpFixedWindow(context, 20, TimeSpan.FromMinutes(1)));
            options.OnRejected = (context, _) =>
            {
                context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("AuthEvents")
                    .LogWarning("Auth event {EventType}: result {Result}, path {Path}, trace {TraceId}",
                        "rate-limit", "rejected", context.HttpContext.Request.Path.Value,
                        context.HttpContext.TraceIdentifier);
                return ValueTask.CompletedTask;
            };
        });

        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.UseRateLimiter();

        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            var errors = ValidateRegistration(input);
            if (errors.Count > 0) return Results.ValidationProblem(errors);

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = input.UserName!.Trim(),
                Email = input.Email!.Trim(),
                DisplayName = input.DisplayName!.Trim()
            };

            var result = await users.CreateAsync(user, input.Password!);
            if (!result.Succeeded)
            {
                var codes = result.Errors.Select(e => e.Code).ToArray();

                if (codes.Contains("DuplicateUserName") || codes.Contains("DuplicateEmail"))
                    return Results.Problem(statusCode: StatusCodes.Status409Conflict,
                        title: "Conflict", detail: "Обліковий запис із такими даними вже існує.");

                if (codes.Any(c => c.StartsWith("Password")))
                    return Results.ValidationProblem(new Dictionary<string, string[]>
                    {
                        ["password"] = ["Пароль має містити щонайменше 10 символів, велику й малу "
                                      + "латинські літери, цифру та спецсимвол."]
                    });

                if (codes.Contains("InvalidUserName"))
                    return Results.ValidationProblem(new Dictionary<string, string[]>
                        { ["userName"] = ["userName містить недозволені символи."] });

                if (codes.Contains("InvalidEmail"))
                    return Results.ValidationProblem(new Dictionary<string, string[]>
                        { ["email"] = ["email має неправильний формат."] });

                return Results.Problem(statusCode: StatusCodes.Status400BadRequest,
                    title: "Registration failed");
            }

            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");

            return Results.Created("/api/me",
                new RegistrationResponse(user.Id, user.UserName!, user.DisplayName));
        }).RequireRateLimiting("register");

        app.MapPost("/api/auth/login", async (LoginInput input, HttpContext context,
            SignInManager<ApplicationUser> signIn, ILoggerFactory loggerFactory) =>
        {
            var log = loggerFactory.CreateLogger("AuthEvents");

            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                log.LogWarning("Auth event {EventType}: result {Result}, user {UserFingerprint}, trace {TraceId}",
                    "login", "rejected-input", Fingerprint(input.UserName), context.TraceIdentifier);
                return Results.Unauthorized();
            }

            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);

            if (result.Succeeded)
            {
                log.LogInformation("Auth event {EventType}: result {Result}, user {UserFingerprint}, trace {TraceId}",
                    "login", "success", Fingerprint(input.UserName), context.TraceIdentifier);
                return Results.NoContent();
            }

            log.LogWarning("Auth event {EventType}: result {Result}, user {UserFingerprint}, trace {TraceId}",
                "login", "failed", Fingerprint(input.UserName), context.TraceIdentifier);
            return Results.Unauthorized();
        }).RequireRateLimiting("login");

        app.MapPost("/api/auth/logout", async (HttpContext context,
            SignInManager<ApplicationUser> signIn, ILoggerFactory loggerFactory) =>
        {
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
            await signIn.SignOutAsync();
            loggerFactory.CreateLogger("AuthEvents")
                .LogInformation("Auth event {EventType}: result {Result}, user {UserId}, trace {TraceId}",
                    "logout", "success", userId, context.TraceIdentifier);
            return Results.NoContent();
        });

        app.MapGet("/api/me", async (HttpContext context, UserManager<ApplicationUser> users) =>
        {
            // Ідентифікатор береться ЛИШЕ з перевіреного principal (cookie), не з header/body/query.
            var idValue = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!Guid.TryParse(idValue, out var verifiedId))
                return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);

            var user = await users.FindByIdAsync(verifiedId.ToString());
            if (user is null)
                return Results.Unauthorized();

            return Results.Ok(new MeResponse(user.Id, user.UserName!, user.DisplayName));
        }).RequireAuthorization();

        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    // Ключ обмеження: IP-адреса клієнта. Лімітер веде окремий лічильник для кожної адреси.
    private static RateLimitPartition<string> IpFixedWindow(HttpContext context, int permits, TimeSpan window)
        => RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permits,
                Window = window,
                QueueLimit = 0
            });

    // У журнал йде не ім'я користувача, а короткий відбиток.
    private static string Fingerprint(string? userName)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes((userName ?? "").Trim().ToLowerInvariant()));
        return Convert.ToHexString(bytes)[..8];
    }

    private static Dictionary<string, string[]> ValidateRegistration(RegistrationInput input)
    {
        var errors = new Dictionary<string, string[]>();

        var userName = input.UserName?.Trim();
        if (string.IsNullOrEmpty(userName))
            errors["userName"] = ["userName є обов'язковим."];
        else if (userName.Length is < 3 or > 64)
            errors["userName"] = ["userName має бути від 3 до 64 символів."];
        else if (!userName.All(c => char.IsAsciiLetterOrDigit(c) || "-._@+".Contains(c)))
            errors["userName"] = ["userName містить недозволені символи."];

        var email = input.Email?.Trim();
        if (string.IsNullOrEmpty(email))
            errors["email"] = ["email є обов'язковим."];
        else if (email.Length > 256)
            errors["email"] = ["email має бути не довшим за 256 символів."];

        var displayName = input.DisplayName?.Trim();
        if (string.IsNullOrEmpty(displayName))
            errors["displayName"] = ["displayName є обов'язковим."];
        else if (displayName.Length > 120)
            errors["displayName"] = ["displayName має бути не довшим за 120 символів."];

        if (string.IsNullOrEmpty(input.Password))
            errors["password"] = ["password є обов'язковим."];
        else if (input.Password.Length > 128)
            errors["password"] = ["password має бути не довшим за 128 символів."];

        return errors;
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);
public sealed record RegistrationResponse(Guid Id, string UserName, string DisplayName);
public sealed record MeResponse(Guid Id, string UserName, string DisplayName);