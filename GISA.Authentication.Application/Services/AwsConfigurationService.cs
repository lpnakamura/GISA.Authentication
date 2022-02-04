using GISA.Authentication.Application.Interfaces;
using Microsoft.Extensions.Configuration;

namespace GISA.Authentication.Application.Services
{
    public class AwsConfigurationService : ICloudConfigurationService
    {
        private readonly IConfiguration _configuration;

        public AwsConfigurationService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GetAccessKey()
        {
            return this._configuration.GetSection("AWS").GetValue<string>("AccessKey");
        }

        public string GetRegion()
        {
            return this._configuration.GetSection("AWS").GetValue<string>("Region");
        }

        public string GetSecretKey()
        {
            return this._configuration.GetSection("AWS").GetValue<string>("SecretKey");
        }

        public string GetUserPoolClientId()
        {
             return this._configuration.GetSection("AWS").GetValue<string>("UserPoolClientId");
        }

        public string GetUserPoolClientSecret()
        {
            return this._configuration.GetSection("AWS").GetValue<string>("UserPoolClientSecret");
        }

        public string GetUserPoolId()
        {
            return this._configuration.GetSection("AWS").GetValue<string>("UserPoolId");
        }
    }
}