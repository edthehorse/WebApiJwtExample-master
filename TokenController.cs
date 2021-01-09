using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace WebApiJwtExample
{
    [Route("/token")]
    public class TokenController : Controller
    {        
        [HttpPost] // Step 4 : Returns the token to the client.
        public IActionResult Create(string username, string password) // Responds to the Create Post.
        {
            if (IsValidUserAndPasswordCombination(username, password)) // Pass simple test first.
            {
                string s = GenerateToken(username);  // Server code ! Generates the token. A helper function. Only use the uname not the p/word in this case.

                return new ObjectResult(s); // ObjectResult is simply part of Microsoft.AspNetCore.Mvc. ie an object is returned. ie Json object? 
                                            // ie Returns the token back to the form as a response. ie The server generated this Token ??
                                            // ie sends it to the client.
                // If all goes well with the POST you get the JWT BACK and you can save it somewhere- usually in local storage in the case of a web app.
            }
            return BadRequest();
        }

        private bool IsValidUserAndPasswordCombination(string username, string password) // Simply tests if u/name * password are 1. not null. 2. equal.
        {
            return !string.IsNullOrEmpty(username) && username == password; // We decide that being equal is OK for testing.
        }

        private string GenerateToken(string username)  // Step2:  Our token consists of 3 claims.
        {
            var claims = new Claim[] // 3 Claims: ed, Date now &  Expiry date.
            {
                new Claim(ClaimTypes.Name, username), // ClaimTypes.Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", ed. ed

                new Claim(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds().ToString()), // Nbf (Not before), DateTime.Now = {20/12/2020 12:42:53}

                new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(DateTime.Now.AddDays(1)).ToUnixTimeSeconds().ToString()), // Exp (Expiry), One day later

            };

            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("the secret that needs to be at least 16 characeters long for HmacSha256")); // Mine: ed  : 27 bytes encryption. // Private key !
            // Not used in the sending of the token!
            
            // THE TOKEN to be sent by the client.
            var token = new JwtSecurityToken(   // Step 1 : Make a new token. (I guess this JwtSecurityToken automatically makes the header: { "alg":"HS256","typ":"JWT"}

                new JwtHeader(new SigningCredentials(

                // This is the body of the token (unencrypted!). The message along with the hash algorithm to be used (Sha256).
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes("My not so secret message - it needs to be at least 16 characters long for HmacSha256")), SecurityAlgorithms.HmacSha256)),

    // Therefore the RESULTING TOKEN is:
    // token = { { "alg":"HS256","typ":"JWT"}.{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
    
    // My token happens to be:  "ed","nbf":"1608468078","exp":"1608554478"}}
    // From the Locals window: 
    // Claims = Count = 3  ie ed & the 2 dates.        
    // EncodedHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // This is encoded - not encrypted. Just ascii (sort of) bytes! Same for the payload.
    // EncodedPayload = "eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIjoiZWQiLCJuYmYiOiIxNjA4NDY4MDc4IiwiZXhwIjoiMTYwODU1NDQ3OCJ9"
    // Header = Count = 2 ie "alg":"HS256" & "typ":"JWT"

            new JwtPayload(claims));

            return new JwtSecurityTokenHandler().WriteToken(token); // Step3: Write actually generates the token.
        }
    }
}