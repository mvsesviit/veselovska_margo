using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public static class CookieClient
{
    public static async Task<HttpClient> LoginAsync(
        this SecureLabApiFactory factory,
        string userName,
        string password)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        var response = await client.PostAsJsonAsync(
            "/api/auth/login",
            new { userName, password });

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            response.Dispose();

            await Task.Delay(TimeSpan.FromSeconds(11));

            response = await client.PostAsJsonAsync(
                "/api/auth/login",
                new { userName, password });
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                client.Dispose();
                throw new InvalidOperationException(
                    $"Study login failed: HTTP {(int)response.StatusCode} ({response.StatusCode}); credentials omitted.");
            }
        }

        return client;
    }
}
