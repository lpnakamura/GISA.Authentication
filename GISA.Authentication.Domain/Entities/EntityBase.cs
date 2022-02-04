using FluentValidation.Results;

namespace GISA.Authentication.Domain.Entities
{
    public abstract class EntityBase
    {
        public bool Valid { get; private set; }
        public bool Invalid => !Valid;
        public ValidationResult ValidationResult { get; private set; }

        public abstract ValidationResult GetValidationResult<TModel>();

        public bool Validate<TModel>(TModel model)
        {
            ValidationResult = this.GetValidationResult<TModel>();
            return Valid = ValidationResult.IsValid;
        }        
    }
}