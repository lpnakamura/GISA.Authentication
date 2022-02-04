
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using GISA.Authentication.Application;
using GISA.Authentication.Application.Notifications;
using GISA.Authentication.Application.ViewModels;

namespace GISA.Authentication.WebApi.Controllers
{
    [ApiController]
    [ApiVersion("1")]
    [Route("api/v{version:apiVersion}/[controller]")]
    public class AuthenticationController : ApiBaseController
    {
        private readonly IAuthenticationService _authenticationService;

        public AuthenticationController(IAuthenticationService authenticationService, NotificationContext notificationContext) : base(notificationContext)
        {
            _authenticationService = authenticationService;
        }

        [HttpPost("signup")]
        public async Task<IActionResult> SignUp(SignUpRequestViewModel signUpViewModel)
        {
            var signUpResponse = await _authenticationService.SignUp(signUpViewModel);
            return CustomResponse(CreatedAtAction("SignUp", signUpResponse));
        }

        [HttpPost("signout")]
        public async Task<IActionResult> SignOut(SignOutRequestViewModel signOutViewModel)
        {
            await _authenticationService.SignOut(signOutViewModel);
            return CustomResponse();
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordRequestViewModel forgotPasswordViewModel)
        {
            await _authenticationService.ForgotPassword(forgotPasswordViewModel);
            return CustomResponse();
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequestViewModel resetPasswordViewModel)
        {
            await _authenticationService.ResetPassword(resetPasswordViewModel);
            return CustomResponse();
        }

        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordRequestViewModel changePasswordRequestViewModel)
        {
            await _authenticationService.ChangePassword(changePasswordRequestViewModel);
            return CustomResponse();
        }

        [HttpPost("change-email")]
        public async Task<IActionResult> ChangeEmail(ChangeEmailRequestViewModel changeEmailRequestViewModel)
        {
            await _authenticationService.ChangeEmail(changeEmailRequestViewModel);
            return CustomResponse();
        }

        [HttpPost("confirm")]
        public async Task<IActionResult> ConfirmSignUp(ConfirmSignUpRequestViewModel confirmSignUpViewModel)
        {
            await _authenticationService.ConfirmSignUp(confirmSignUpViewModel);
            return CustomResponse();
        }

        [HttpPost("resend")]
        public async Task<IActionResult> ResendConfirmationCodeSignUp(ResendConfirmationCodeRequestViewModel resendConfirmationCodeViewModel)
        {
            await _authenticationService.ResendConfirmationCode(resendConfirmationCodeViewModel);
            return CustomResponse();
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequestViewModel loginViewModel)
        {
            var loginResponse = await _authenticationService.Login(loginViewModel);
            return CustomResponse(Ok(loginResponse));
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken(RefreshTokenRequestViewModel refreshTokenViewModel)
        {
            var refreshTokenResponse = await _authenticationService.RefreshToken(refreshTokenViewModel);
            return CustomResponse(Ok(refreshTokenResponse));
        }
    }
}
