using FluentValidation.Results;
using GISA.Authentication.Domain.Validators;

namespace GISA.Authentication.Domain.Entities
{
    public class ConfirmSignUp : EntityBase
    {
        public string UserName { get; set; }
        public string Code { get; set; }

        public override ValidationResult GetValidationResult<ConfirmSignUp>()
        {
            return new ConfirmSignUpValidator().Validate(this);
        }
    }
}