namespace GISA.Authentication.Application.Interfaces
{
    public interface ICloudConfigurationService
    {
        string GetAccessKey();
        string GetSecretKey();
        string GetRegion();
        string GetUserPoolClientId();
        string GetUserPoolId();
        string GetUserPoolClientSecret();
    }
}