using AuthenticationLibraryCore.JWT.Managers;
using AuthenticationLibraryCore.JWT.Models;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace AuthenticationLibraryCore.Tests
{
    public class Tests
    {
        [SetUp]
        public void Setup()
        {

        }

        [Test]
        public void IsTokenValid()
        {
            //ARRANGER
            var Id = Guid.NewGuid();
            var secretKey = "that's a single secret key used to not be hacked";
            var claimsRequest = new Dictionary<string, string>();

            claimsRequest.Add(eClaims.Name.ToString(), "Luca Fenu");
            claimsRequest.Add(eClaims.Id.ToString(), Id.ToString());
            claimsRequest.Add(eClaims.Mail.ToString(), "email@email.it");
            IAuthContainerModel model = new JWTContainerModel(secretKey, 1, "http://localhost:123", claimsRequest);

            //ACT

            IAuthService authService = new JWTService(model);
            string token = authService.GenerateToken();

            //ASSERT
            Assert.IsTrue(authService.IsTokenValid(token));
        }

        [Test]
        public void IsTokenValidFromDifferentInstance()
        {
            //ARRANGER
            var Id = Guid.NewGuid();
            var secretKey = "that's a single secret key used to not be hacked";
            var claimsRequest = new Dictionary<string, string>();

            claimsRequest.Add(eClaims.Name.ToString(), "Luca Fenu");
            claimsRequest.Add(eClaims.Id.ToString(), Id.ToString());
            claimsRequest.Add(eClaims.Mail.ToString(), "email@email.it");
            IAuthContainerModel model = new JWTContainerModel(secretKey, 1, "http://localhost:123", claimsRequest);

            //ACT

            IAuthService authService = new JWTService(model);

            string token = authService.GenerateToken();

            IAuthContainerModel modelResponse = new JWTContainerModel(secretKey, 1, "http://localhost:123", null);
            IAuthService authServiceResponse = new JWTService(modelResponse);

            var tokenResponse = authServiceResponse.GenerateToken();

            //ASSERT
            Assert.IsTrue(authService.IsTokenValid(tokenResponse));
        }


        [Test]
        public void KO_IssuerNotMatch()
        {
            //ARRANGER
            var Id = Guid.NewGuid();
            var secretKey = "that's a single secret key used to not be hacked";
            var claimsRequest = new Dictionary<string, string>();

            claimsRequest.Add(eClaims.Name.ToString(), "Luca Fenu");
            claimsRequest.Add(eClaims.Id.ToString(), Id.ToString());
            claimsRequest.Add(eClaims.Mail.ToString(), "email@email.it");

            //ACT
            IAuthContainerModel model = new JWTContainerModel(secretKey, 1, "http://localhost:123", claimsRequest);

            IAuthService authService = new JWTService(model);

            string token = authService.GenerateToken();

            IAuthContainerModel modelResponse = new JWTContainerModel(secretKey, 1, "http://localhost:312", null);
            IAuthService authServiceResponse = new JWTService(modelResponse);

            var tokenResponse = authServiceResponse.GenerateToken();

            //ASSERT
            Assert.IsFalse(authService.IsTokenValid(tokenResponse));
        }


        public enum eClaims
        {
            Id,
            Name,
            Mail
        }
    }
}