using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Text;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("b2bAPIDB") ?? "Data Source=b2bAPI.db;Cache=Shared";
var sharedSaltKey = builder.Configuration.GetConnectionString("SharedSaltKey") ?? "SHAREDSALTKEY";

builder.Services.AddScoped(_ => new SqliteConnection(connectionString));
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

await EnsureDb(app.Services, app.Logger);

app.MapSwagger();
app.UseSwaggerUI();

app.MapGet("/", () => "Hello World!")
   .WithName("Hello");

app.MapPost("/gettoken", async ([FromBody] GetTokenModel model, SqliteConnection db) =>
{
    var query = $@"SELECT * FROM Users WHERE UserName='{model.UserName}' AND Password='{model.Password}'";

    if (await db.QuerySingleOrDefaultAsync<User>(query) is User user)
    {
        if (!DateTime.TryParseExact(model.ProcessDate, "yyyyMMddHHmmss",
            CultureInfo.InvariantCulture, DateTimeStyles.None, out global::System.DateTime processDate))
        {
            return Results.Problem("Process date is not valid.");
        }

        if ((DateTime.Now - processDate).TotalHours > 1)
        {
            return Results.Problem("Process date is not valid.");
        }

        var modelStr = model.ToString();

        var createSignatureForCompare = model.ToString() + sharedSaltKey;

        var hashOfCreatedSignature = new StringBuilder();

        using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
        {
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(createSignatureForCompare);
            byte[] hashBytes = md5.ComputeHash(inputBytes);

            // Convert the byte array to hexadecimal string
            for (int i = 0; i < hashBytes.Length; i++)
            {
                hashOfCreatedSignature.Append(hashBytes[i].ToString("X2"));
            }
        }

        if (model.Signature != hashOfCreatedSignature.ToString()) return Results.Problem("Invalid signature!");

        var token = Guid.NewGuid();

        var createTokenRecordQuery = @"INSERT OR IGNORE INTO Tokens (UserId, TokenString, CreateDate, ExpireDate)"
        + $" VALUES({user.Id},'{token}','{DateTime.Now}','{DateTime.Now.AddHours(1)}')";

        await db.ExecuteAsync(createTokenRecordQuery);

        return Results.Ok(token);
    }

    return Results.NotFound("User not found!");

}).AllowAnonymous();

app.MapPost("/oursecurejob", async (string tokenString, SqliteConnection db) =>
{
    var query = $@"SELECT * FROM Tokens WHERE TokenString='{tokenString}' AND ExpireDate < DATE('now')";

    if (await db.QuerySingleOrDefaultAsync<Token>(query) is Token token)
    {
        return Results.Ok("Our secure job executed!");
    }

    return Results.NotFound("Token not found!");
});

app.Run();

async Task EnsureDb(IServiceProvider services, ILogger logger)
{
    logger.LogInformation("Ensuring database exists at connection string '{connectionString}'", connectionString);

    using var db = services.CreateScope().ServiceProvider.GetRequiredService<SqliteConnection>();

    var createUserTableQuery = $@"CREATE TABLE IF NOT EXISTS Users (
                  {nameof(User.Id)} INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                  {nameof(User.UserName)} TEXT NOT NULL,
                  {nameof(User.Password)} TEXT NOT NULL);";
    
    await db.ExecuteAsync(createUserTableQuery);

    var createUserRecordQuery = $@"INSERT OR IGNORE INTO Users VALUES(1, 'canurek', '123456')";

    await db.ExecuteAsync(createUserRecordQuery);

    var createTokenTableQuery = $@"CREATE TABLE IF NOT EXISTS Tokens (
                  {nameof(Token.Id)} INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                  {nameof(Token.UserId)} INTEGER,
                  {nameof(Token.TokenString)} TEXT NOT NULL,
                  {nameof(Token.CreateDate)} DATETIME NOT NULL,
                  {nameof(Token.ExpireDate)} DATETIME NOT NULL);";

    await db.ExecuteAsync(createTokenTableQuery);
}

class User
{
    public int Id { get; set; }
    [Required]
    public string? UserName { get; set; }
    [Required]
    public string? Password { get; set; }
}

class Token
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string? TokenString { get; set; }
    public DateTime CreateDate { get; set; }
    public DateTime ExpireDate { get; set; }
}

class GetTokenModel
{
    public string? UserName { get; set; }
    public string? Password { get; set; }
    public string? ProcessDate { get; set; }
    public string? Signature { get; set; }

    public override string ToString()
    {
        return string.Concat(UserName, Password, ProcessDate);
    }
}