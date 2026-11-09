using System.Net;
using System.Net.Http.Json;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class IncidentCommentAuthorizationTests(
    SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException(
            "Set local SeedUsers__Password outside Git.");

    private const string AliceCommentId =
        "30000000-0000-0000-0000-000000000001";

    private const string BobCommentId =
        "30000000-0000-0000-0000-000000000002";

    private const string BobInternalCommentId =
        "30000000-0000-0000-0000-000000000003";

    [Fact]
    public async Task Reporter_CanReadOwnPublicComment()
    {
        using var client = await factory.LoginAsync(
            "alice", StudyPassword);

        using var response = await client.GetAsync(
            $"/api/incident-comments/{AliceCommentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var comment =
            await response.Content.ReadFromJsonAsync<IncidentCommentResponse>();

        Assert.NotNull(comment);
        Assert.Equal(
            "Заголовки листа передано аналітику.",
            comment.Text);
    }

    [Fact]
    public async Task Reporter_CannotReadAnotherUsersComment()
    {
        using var client = await factory.LoginAsync(
            "alice", StudyPassword);

        using var response = await client.GetAsync(
            $"/api/incident-comments/{BobCommentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Reporter_CannotReadInternalComment()
    {
        using var client = await factory.LoginAsync(
            "bob", StudyPassword);

        using var response = await client.GetAsync(
            $"/api/incident-comments/{BobInternalCommentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Analyst_CanReadInternalComment()
    {
        using var client = await factory.LoginAsync(
            "morgan", StudyPassword);

        using var response = await client.GetAsync(
            $"/api/incident-comments/{BobInternalCommentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var comment =
            await response.Content.ReadFromJsonAsync<IncidentCommentResponse>();

        Assert.NotNull(comment);
        Assert.Equal(
            "Внутрішня примітка: перевірити джерело спроби входу.",
            comment.Text);
    }
    [Fact]
public async Task Administrator_CanReadInternalComment()
{
    using var client = await factory.LoginAsync("admin", StudyPassword);

    using var response = await client.GetAsync(
        $"/api/incident-comments/{BobInternalCommentId}");

    Assert.Equal(HttpStatusCode.OK, response.StatusCode);

    var comment = await response.Content
        .ReadFromJsonAsync<IncidentCommentResponse>();

    Assert.NotNull(comment);
    Assert.Equal(
        "Внутрішня примітка: перевірити джерело спроби входу.",
        comment.Text);
}
}