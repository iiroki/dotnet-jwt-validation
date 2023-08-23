using System.IdentityModel.Tokens.Jwt;
using System.Text;
using dotenv.net;
using Microsoft.IdentityModel.Tokens;

// JWT: Symmetric Key Encryption
// Validate JWT with a symmetric key created from JWT secret key.

DotEnv.Load();

var jwt = Environment.GetEnvironmentVariable("JWT");
var jwtAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE");
var jwtIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER");
var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET");
if (string.IsNullOrEmpty(jwtSecret))
{
    throw new ArgumentException("'JWT_SECRET' env variable is null or empty");
}

// Create JWT validation parameters
var jwtSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
var jwtValidationParams = new TokenValidationParameters
{
    ValidateLifetime = true,
    ValidateAudience = true,
    ValidateIssuer = true,
    ValidateIssuerSigningKey = true,
    ValidAudience = jwtAudience,
    ValidIssuer = jwtIssuer,
    IssuerSigningKey = jwtSigningKey,
    // ValidAlgorithms = new[] { "HS256" }
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
