
using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class SecurityStampTests(
    SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task ChangingSecurityStamp_InvalidatesOldCookie()
    {
        // 1. Отримуємо пароль тестового користувача.
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException(
                "Set local SeedUsers__Password outside Git.");

        // 2. Виконуємо справжній вхід і отримуємо cookie.
        using var client = await factory.LoginAsync("alice", password);

        // 3. Переконуємося, що початковий сеанс чинний.
        using var before = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        // 4. Змінюємо Security Stamp користувача Alice.
        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();

            var user = await userManager.FindByNameAsync("alice");

            Assert.NotNull(user);

            var updateResult =
                await userManager.UpdateSecurityStampAsync(user);

            Assert.True(updateResult.Succeeded);
        }

        // 5. Перевіряємо старий cookie після зміни stamp.
        using var after = await client.GetAsync("/api/me");

        // 6. Старий сеанс повинен бути відхилений.
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }
}
