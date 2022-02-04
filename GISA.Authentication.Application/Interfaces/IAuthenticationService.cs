using System.Threading.Tasks;
using GISA.Authentication.Application.ViewModels;

namespace GISA.Authentication.Application
{
    public interface IAuthenticationService
    {
        Task<SignUpResponseViewModel> SignUp(SignUpRequestViewModel signUpViewModel);
        Task<bool> SignOut(SignOutRequestViewModel signOutViewModel);
        Task<bool> ConfirmSignUp(ConfirmSignUpRequestViewModel confirmSignUpViewModel);
        Task<LoginResponseViewModel> Login(LoginRequestViewModel loginViewModel);        
        Task<LoginResponseViewModel> RefreshToken(RefreshTokenRequestViewModel refreshTokenViewModel);
        Task<bool> ResendConfirmationCode(ResendConfirmationCodeRequestViewModel resendConfirmationCodeViewModel);
        Task<bool> ForgotPassword(ForgotPasswordRequestViewModel forgotPasswordViewModel);
        Task<bool> ResetPassword(ResetPasswordRequestViewModel resetPasswordRequestViewModel);
        Task<bool> ChangePassword(ChangePasswordRequestViewModel changePasswordRequestViewModel);
        Task<bool> ChangeEmail(ChangeEmailRequestViewModel changeEmailRequestViewModel);
    }
}