using System.IdentityModel.Tokens.Jwt;
using dotenv.net;
using Microsoft.IdentityModel.Tokens;

// JWT: Asymmetric Key Encryption
// Validate JWT with a public key created from JWKS.

DotEnv.Load();

var jwt = Environment.GetEnvironmentVariable("JWT");
var jwtAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE");
var jwtIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER");
var jwksUrl = Environment.GetEnvironmentVariable("JWKS_URL");
if (string.IsNullOrEmpty(jwksUrl))
{
    throw new ArgumentException("'JWKS_URL' env variable is null or empty");
}

// Fetch JWKS
var httpClient = new HttpClient();
var res = httpClient.GetAsync(jwksUrl).GetAwaiter().GetResult();
var jsonStr = res.Content.ReadAsStringAsync().GetAwaiter().GetResult();

// Create JWT validation parameters
var jwks = new JsonWebKeySet(jsonStr);
var jwtValidationParams = new TokenValidationParameters
{
    ValidateLifetime = true,
    ValidateAudience = true,
    ValidateIssuer = true,
    ValidateIssuerSigningKey = true,
    ValidAudience = jwtAudience,
    ValidIssuer = jwtIssuer,
    IssuerSigningKey = jwks.Keys.First()
};

var jwtHandler = new JwtSecurityTokenHandler();
var validJwt = false;
try
{
    jwtHandler.ValidateToken(jwt, jwtValidationParams, out var validated);
    validJwt = true;
}
catch (Exception ex)
{
    Console.WriteLine(ex);
}

Console.WriteLine($"Is JWT valid: {validJwt}");
