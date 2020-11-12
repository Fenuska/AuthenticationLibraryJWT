using System.Collections.Generic;

namespace AuthenticationLibraryCore.JWT.Managers
{
    public interface IAuthService
    {
        bool IsTokenValid(string token);
        string GenerateToken();
        Dictionary<string, string> GetTokenValues(string token);
    }
}
