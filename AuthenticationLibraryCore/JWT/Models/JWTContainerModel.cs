using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Security.Claims;

namespace AuthenticationLibraryCore.JWT.Models
{

    public class JWTContainerModel : IAuthContainerModel
    {
        /// <summary>
        /// Secret key. Must be a long string. Short string can throw an exception during encryption
        /// </summary>
        public string SecretKey { get; set; }
        /// <summary>
        /// Secure algorithm
        /// </summary>
        public string SecureAlgorithm { get; set; } = SecurityAlgorithms.HmacSha256Signature;
        /// <summary>
        /// Amount of minutes before token expires
        /// </summary>
        public int ExpireMinutes { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public Claim[] Claims { get; set; }
       /// <summary>
       /// 
       /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Model that contains all the data to perform the encryption, and store the secret key for the decryption
        /// </summary>
        /// <param name="secretKey">Secret key. Must be a long string. Short string can throw an exception during encryption</param>
        /// <param name="expireMinutes">Amount of minutes before token expires</param>
        /// <param name="Issuer">Set </param>
        /// <param name="claims">Key value pairs will be decrypted in the token</param>
        public JWTContainerModel(string secretKey, int expireMinutes, string issuer, Dictionary<string, string> claims)
        {
            SecretKey = secretKey;
            ExpireMinutes = expireMinutes;
            Issuer = issuer;

            var claimObjects = new List<Claim>();

            foreach (var keyValue in claims ?? new Dictionary<string, string>())
            {
                claimObjects.Add(new Claim(keyValue.Key, keyValue.Value));
            }

            this.Claims = claimObjects.ToArray();
        }
    }
}
