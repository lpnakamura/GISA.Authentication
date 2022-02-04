using FluentValidation.Results;
using GISA.Authentication.Domain.Validators;

namespace GISA.Authentication.Domain.Entities
{
    public class Login : EntityBase
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public bool RememberMe { get; set; }
        public bool IsEncryptedPassword { get; set; }

        public override ValidationResult GetValidationResult<Login>()
        {
            return new LoginValidator().Validate(this);
        }
    }
}