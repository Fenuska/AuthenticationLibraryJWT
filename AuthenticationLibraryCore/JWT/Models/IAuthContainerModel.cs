using System.Security.Claims;

namespace AuthenticationLibraryCore.JWT.Models
{
    public interface IAuthContainerModel
    {
        string SecretKey { get; set; }
        string SecureAlgorithm { get; set; }
        int ExpireMinutes { get; set; }
        Claim[] Claims { get; set; }
    }
}
