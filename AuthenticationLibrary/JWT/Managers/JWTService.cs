using AuthenticationLibrary.JWT.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthenticationLibrary.JWT.Managers
{
    public class JWTService : IAuthService
    {
        private IAuthContainerModel Model { get; set; }

        public JWTService(IAuthContainerModel model)
        {
            if (model is null || model.Claims is null || model.Claims.Length == 0)
            {
                throw new ArgumentException($"'{nameof(model)}' cannot be null or empty", nameof(model));
            }

            Model = model;
        }

        /// <summary>
        /// Generate a token from the model on the constructor
        /// </summary>
        /// <returns>Token with encrypted data</returns>
        public string GenerateToken()
        {
            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(Model.Claims),
                Expires = DateTime.UtcNow.AddMinutes(Convert.ToInt32(Model.ExpireMinutes)),
                SigningCredentials = new SigningCredentials(GetSummetricSecurityKey(), Model.SecureAlgorithm)
            };

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            string token = jwtSecurityTokenHandler.WriteToken(securityToken);

            return token;
        }

        /// <summary>
        /// Retrieve all the claims on the token
        /// </summary>
        /// <param name="token">Current token to be decrypted</param>
        /// <returns>Dictionary with key value pairs of the token. If it returns an empty dictionary, token is not valid.</returns>
        public Dictionary<string, string> GetTokenValues(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                throw new ArgumentException($"'{nameof(token)}' cannot be null or empty", nameof(token));
            }

            var isTokenValid = IsTokenValid(token);
            if (!isTokenValid)
                return new Dictionary<string, string>();

            TokenValidationParameters tokenValidationParameters = GetTokenValidationParameters();

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                ClaimsPrincipal tokenValid = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);

                var claims = new Dictionary<string, string>();

                foreach (var claim in tokenValid.Claims)
                {
                    claims.Add(claim.Type, claim.Value);
                }

                return claims;
            }
            catch (Exception exception)
            {
                throw exception;
            }
        }

        /// <summary>
        /// Check if the token is still valid
        /// </summary>
        /// <param name="token"></param>
        /// <returns>True is valid, false is expired</returns>
        public bool IsTokenValid(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Given token is null or empty");

            TokenValidationParameters tokenValidationParameters = GetTokenValidationParameters();

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                ClaimsPrincipal tokenValid = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private SecurityKey GetSummetricSecurityKey()
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(Model.SecretKey);
            var key = Convert.ToBase64String(plainTextBytes);

            byte[] symmetricKey = Convert.FromBase64String(key);
            return new SymmetricSecurityKey(symmetricKey);
        }

        private TokenValidationParameters GetTokenValidationParameters()
        {
            return new TokenValidationParameters()
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                IssuerSigningKey = GetSummetricSecurityKey()
            };
        }
    }
}