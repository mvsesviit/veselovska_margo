using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;


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
        description = "РЁС‚СѓС‡РЅРёР№ Р·Р°РїРёСЃ РґР»СЏ РїРµСЂРµРІС–СЂРєРё СЃС‚РІРѕСЂРµРЅРЅСЏ.",
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

    [Fact] // A-01 РЅР° СЃРїСЂР°РІР¶РЅСЊРѕРјСѓ Р·Р°С…РёС‰РµРЅРѕРјСѓ create
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
            description = "РЁС‚СѓС‡РЅРёР№ Р·Р°РїРёСЃ РґР»СЏ РїРµСЂРµРІС–СЂРєРё СЃС‚РІРѕСЂРµРЅРЅСЏ.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddDays(-1),
            ownerUserId = DbSeeder.AliceId
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var owner = await OwnerOf(await CreatedId(response));
        Assert.Equal(DbSeeder.BobId, owner);
        Assert.NotEqual(DbSeeder.AliceId, owner);
    }

    [Fact]
    public async Task Register_Login_CreateIncident_UsesIdentityStoreOwner()
    {
        var oraclePassword = "OracleTest123!";

        // 1. РЎС‚РІРѕСЂСЋС”РјРѕ СѓРЅС–РєР°Р»СЊРЅРµ С–Рј'СЏ РЅРѕРІРѕРіРѕ РєРѕСЂРёСЃС‚СѓРІР°С‡Р°.
        var oracleName = "oracle" + Guid.NewGuid().ToString("N")[..8];

        // 2. Р РµС”СЃС‚СЂСѓС”РјРѕ РЅРѕРІРѕРіРѕ РєРѕСЂРёСЃС‚СѓРІР°С‡Р°.
        using var registrationClient = factory.CreateClient();

        using var registrationResponse = await registrationClient.PostAsJsonAsync(
            "/api/auth/register",
            new
            {
                userName = oracleName,
                email = oracleName + "@example.test",
                displayName = "Oracle Test User",
                password = oraclePassword
            });

        Assert.Equal(HttpStatusCode.Created, registrationResponse.StatusCode);

        // 3. РћС‚СЂРёРјСѓС”РјРѕ Id Р· РІС–РґРїРѕРІС–РґС– СЂРµС”СЃС‚СЂР°С†С–С—.
        using var registrationDoc = JsonDocument.Parse(
            await registrationResponse.Content.ReadAsStringAsync());

        var registrationId = registrationDoc.RootElement
            .GetProperty("id")
            .GetGuid();

        // 4. РќРµР·Р°Р»РµР¶РЅРѕ РѕС‚СЂРёРјСѓС”РјРѕ Id Р· Identity Store С‡РµСЂРµР· UserManager.
        Guid storeId;

        using (var scope = factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();

            var storedUser = await users.FindByNameAsync(oracleName);

            Assert.NotNull(storedUser);
            storeId = storedUser.Id;
        }

        // 5. РџРµСЂРµРІС–СЂСЏС”РјРѕ, С‰Рѕ СЂРµС”СЃС‚СЂР°С†С–СЏ РїРѕРІРµСЂРЅСѓР»Р° Id Р·С– СЃС…РѕРІРёС‰Р°.
        Assert.Equal(storeId, registrationId);

        // 6. Р’С…РѕРґРёРјРѕ РїС–Рґ РЅРѕРІРёРј РєРѕСЂРёСЃС‚СѓРІР°С‡РµРј.
      using var oracle = await factory.LoginAsync(oracleName, oraclePassword);

        // 7. РћС‚СЂРёРјСѓС”РјРѕ РїСЂРѕС„С–Р»СЊ С‡РµСЂРµР· /api/me.
        using var profileResponse = await oracle.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, profileResponse.StatusCode);

        using var profileDoc = JsonDocument.Parse(
            await profileResponse.Content.ReadAsStringAsync());

        var profileId = profileDoc.RootElement
            .GetProperty("id")
            .GetGuid();

        // 8. Id РїСЂРѕС„С–Р»СЋ РїРѕРІРёРЅРµРЅ Р·Р±С–РіР°С‚РёСЃСЏ Р· Id Сѓ СЃС…РѕРІРёС‰С–.
        Assert.Equal(storeId, profileId);

        // 9. РЎС‚РІРѕСЂСЋС”РјРѕ С–РЅС†РёРґРµРЅС‚ С– РЅР°РјР°РіР°С”РјРѕСЃСЏ РїС–РґРјС–РЅРёС‚Рё Р№РѕРіРѕ РІР»Р°СЃРЅРёРєР° РЅР° Alice.
        using var incidentResponse = await oracle.PostAsJsonAsync(
            "/api/incidents",
            new
            {
                title = UniqueTitle(),
                description = "РџРµСЂРµРІС–СЂРєР° РІР»Р°СЃРЅРёРєР° РЅРѕРІРѕРіРѕ С–РЅС†РёРґРµРЅС‚Сѓ.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddDays(-1),
                ownerUserId = DbSeeder.AliceId
            });

        Assert.Equal(HttpStatusCode.Created, incidentResponse.StatusCode);

        // 10. РћС‚СЂРёРјСѓС”РјРѕ Id СЃС‚РІРѕСЂРµРЅРѕРіРѕ С–РЅС†РёРґРµРЅС‚Сѓ.
        var incidentId = await CreatedId(incidentResponse);

        // 11. Р§РёС‚Р°С”РјРѕ С„Р°РєС‚РёС‡РЅРѕРіРѕ РІР»Р°СЃРЅРёРєР° Р±РµР·РїРѕСЃРµСЂРµРґРЅСЊРѕ Р· Р±Р°Р·Рё РґР°РЅРёС….
        var actualOwnerId = await OwnerOf(incidentId);

        // 12. РџРµСЂРµРІС–СЂСЏС”РјРѕ РІР»Р°СЃРЅРёРєР° Р·Р° РЅРµР·Р°Р»РµР¶РЅРёРј Р·РЅР°С‡РµРЅРЅСЏРј Р·С– СЃС…РѕРІРёС‰Р°.
        Assert.Equal(storeId, actualOwnerId);
        Assert.NotEqual(DbSeeder.AliceId, actualOwnerId);
    }

    [Fact]
    public async Task Analyst_CannotCreateIncident()
    {
        using var client = await factory.LoginAsync("morgan", StudyPassword);

        using var response = await client.PostAsJsonAsync(
            "/api/incidents",
            ValidBody("Analyst-forbidden-" + Guid.NewGuid().ToString("N")));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
