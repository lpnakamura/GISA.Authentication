using System;
using System.Threading.Tasks;
using Amazon;
using AutoMapper;
using Amazon.Runtime;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using GISA.Authentication.Application.Exceptions;
using GISA.Authentication.Application.Helpers;
using GISA.Authentication.Application.Interfaces;
using GISA.Authentication.Application.Notifications;
using GISA.Authentication.Application.ViewModels;
using GISA.Authentication.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace GISA.Authentication.Application.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private RegionEndpoint _regionEndpoint;
        private InitiateAuthRequest _loginIdentityProviderRequest;

        private InitiateAuthRequest _refreshTokenIdentityProviderRequest;
        private RegionEndpoint RegionEndpoint
        {
            get
            {
                if (_regionEndpoint == null) _regionEndpoint = RegionEndpoint.GetBySystemName(_cloudConfigurationService.GetRegion());
                return _regionEndpoint;
            }
        }

        private InitiateAuthRequest LoginIdentityProviderRequest
        {
            get
            {
                if (_loginIdentityProviderRequest == null)
                    _loginIdentityProviderRequest = new InitiateAuthRequest
                    {
                        ClientId = _cloudConfigurationService.GetUserPoolClientId(),
                        AuthFlow = AuthFlowType.USER_PASSWORD_AUTH,
                        AuthParameters = new Dictionary<string, string>(){
                            {"USERNAME",string.Empty},
                            {"PASSWORD",string.Empty},
                            {"SECRET_HASH", string.Empty}
                        }
                    };

                return _loginIdentityProviderRequest;
            }
        }

        private InitiateAuthRequest RefreshTokenIdentityProviderRequest
        {
            get
            {
                if (_refreshTokenIdentityProviderRequest == null)
                    _refreshTokenIdentityProviderRequest = new InitiateAuthRequest
                    {
                        ClientId = _cloudConfigurationService.GetUserPoolClientId(),
                        AuthFlow = AuthFlowType.REFRESH_TOKEN_AUTH,
                        AuthParameters = new Dictionary<string, string>(){
                            {"USERNAME",string.Empty},
                            {"SECRET_HASH", string.Empty}
                        }
                    };

                return _refreshTokenIdentityProviderRequest;
            }
        }

        private AmazonCognitoIdentityProviderClient IdentityProvider
        {
            get
            {
                return new AmazonCognitoIdentityProviderClient(RegionEndpoint);
            }
        }

        private readonly IMapper _mapper;
        private readonly ICloudConfigurationService _cloudConfigurationService;
        private readonly NotificationContext _notificationContext;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _userPool;
        private readonly IAmazonCognitoIdentityProvider _amazonCognitoIdentityProvider;
        private readonly ILogger<AuthenticationService> _logger;

        public AuthenticationService(IMapper mapper, ICloudConfigurationService cloudConfigurationService, NotificationContext notificationContext, UserManager<CognitoUser> userManager, CognitoUserPool userPool, IAmazonCognitoIdentityProvider amazonCognitoIdentityProvider, ILogger<AuthenticationService> logger)
        {
            _mapper = mapper;
            _cloudConfigurationService = cloudConfigurationService;
            _notificationContext = notificationContext;
            _userManager = userManager;
            _userPool = userPool;
            _amazonCognitoIdentityProvider = amazonCognitoIdentityProvider;
            _logger = logger;
        }

        public async Task<SignUpResponseViewModel> SignUp(SignUpRequestViewModel signUpViewModel)
        {
            try
            {
                var signUp = BuildMapper<SignUp>(signUpViewModel);

                CheckAndRegisterInvalidNotifications(signUp);

                if (signUp.Invalid) return null;

                var user = await FindUserByNameAsync(signUp.UserName) ?? BuildUserObject(signUp.UserName);

                if (user != null && user.Status != null) throw new UsernameExistsException($"The user {signUp.UserName} already exists");

                var createdUser = await _amazonCognitoIdentityProvider.SignUpAsync(BuildSignUpRequest(signUp)).ConfigureAwait(false);

                return _mapper.Map<SignUpResponseViewModel>(signUp);
            }
            catch (UsernameExistsException usernameExistsException)
            {
                AddUsernameExistsExceptionNotification(usernameExistsException);
            }
            catch (Exception exception)
            {
                AddGenericExceptionValidatorNotification(exception);
            }

            return new SignUpResponseViewModel();
        }

        public async Task<bool> SignOut(SignOutRequestViewModel signOutViewModel)
        {
            try
            {
                var signOut = BuildMapper<SignOut>(signOutViewModel);

                CheckAndRegisterInvalidNotifications(signOut);

                if (signOut.Invalid) return false;

                var user = await FindUserByNameAsync(signOut.UserName);

                ValidateUserNotFoundException(user, signOut.UserName);

                user.SignOut();

                return true;
            }
            catch (UserNotFoundException userNotFoundException)
            {
                AddUserNotFoundExceptionNotification(userNotFoundException);
            }
            catch (Exception exception)
            {
                AddGenericExceptionValidatorNotification(exception);
            }

            return false;
        }

        public async Task<bool> ConfirmSignUp(ConfirmSignUpRequestViewModel confirmSignUpViewModel)
        {
            try
            {
                var confirmSignUp = BuildMapper<ConfirmSignUp>(confirmSignUpViewModel);

                CheckAndRegisterInvalidNotifications(confirmSignUp);

                if (confirmSignUp.Invalid) return false;

                var user = await FindUserByNameAsync(confirmSignUp.UserName);

                ValidateUserNotFoundException(user, confirmSignUp.UserName);

                var confirmedUser = await _amazonCognitoIdentityProvider.ConfirmSignUpAsync(BuildConfirmSignUpRequest(confirmSignUp)).ConfigureAwait(false);

                return true;
            }
            catch (UserNotFoundException userNotFoundException)
            {
                AddUserNotFoundExceptionNotification(userNotFoundException);
            }
            catch (UserNotConfirmedException userNotConfirmedException)
            {
                AddUserNotConfirmedExceptionNotification(userNotConfirmedException);
            }
            catch (Exception exception)
            {
                AddGenericExceptionValidatorNotification(exception);
            }

            return false;
        }

        public async Task<bool> ChangeEmail(ChangeEmailRequestViewModel changeEmailRequestViewModel)
        {
            try
            {
                var changeEmail = BuildMapper<ChangeEmail>(changeEmailRequestViewModel);

                CheckAndRegisterInvalidNotifications(changeEmail);

                if (changeEmail.Invalid) return false;

                var user = await FindUserByNameAsync(changeEmail.UserName);

                if (user != null)
                    using (var identityProviderClient = IdentityProvider)
                        await identityProviderClient.AdminDeleteUserAsync(BuildAdminDeleteUserRequest(changeEmail));


                await SignUp(BuildMapper<SignUpRequestViewModel>(changeEmailRequestViewModel));

                return true;
            }
            catch (Exception exception)
            {
                AddGenericExceptionValidatorNotification(exception);
            }

            return false;
        }

        public async Task<bool> ChangePassword(ChangePasswordRequestViewModel changePasswordRequestViewModel)
        {
            try
            {
                var changePassword = BuildMapper<ChangePassword>(changePasswordRequestViewModel);

                CheckAndRegisterInvalidNotifications(changePassword);

                if (changePassword.Invalid) return false;

                var user = await FindUserByNameAsync(changePassword.UserName);

                if (user != null)
                    using (var identityProviderClient = IdentityProvider)
                        await identityProviderClient.AdminDeleteUserAsync(BuildAdminDeleteUserRequest(changePassword));

                await SignUp(BuildMapper<SignUpRequestViewModel>(changePasswordRequestViewModel));

                return true;
            }
            catch (Exception exception)
            {
                AddGenericExceptionValidatorNotification(exception);
            }

            return false;
        }

        public async Task<LoginResponseViewModel> Login(LoginRequestViewModel loginViewModel)
        {
            try
            {
                var login = BuildMapper<Login>(loginViewModel);

                CheckAndRegisterInvalidNotifications(login);

                if (login.Invalid) return null;

                using (var identityProviderClient = IdentityProvider)
                {
                    AddLoginParameters(loginViewModel);
                    InitiateAuthResponse authResponse = await identityProviderClient.InitiateAuthAsync(LoginIdentityProviderRequest);
                    return _mapper.Map<LoginResponseViewModel>(authResponse.AuthenticationResult);
                }
            }
            catch (NotAuthorizedException notAuthorizedException)
            {
                AddNotAuthorizedExceptionNotification(notAuthorizedException);
            }
            catch (UserNotConfirmedException userNotConfirmedException)
            {
                AddUserNotConfirmedExceptionNotification(userNotConfirmedException);
            }
            catch (AmazonServiceException amazonServiceException)
            {
                AddAmazonServiceExceptionNotification(amazonServiceException);
            }
            catch (Exception exception)
            {
                AddGenericExceptionValidatorNotification(exception);
            }

            return new LoginResponseViewModel();
        }

        public async Task<LoginResponseViewModel> RefreshToken(RefreshTokenRequestViewModel refreshTokenViewModel)
        {
            try
            {
                var refreshToken = BuildMapper<RefreshToken>(refreshTokenViewModel);

                CheckAndRegisterInvalidNotifications(refreshToken);

                if (refreshToken.Invalid) return null;

                using (var identityProviderClient = IdentityProvider)
                {
                    AddRefreshTokenParameters(refreshTokenViewModel);
                    InitiateAuthResponse authResponse = await identityProviderClient.InitiateAuthAsync(RefreshTokenIdentityProviderRequest);
                    return _mapper.Map<LoginResponseViewModel>(authResponse.AuthenticationResult);
                }
            }
            catch (NotAuthorizedException notAuthorizedException)
            {
                AddNotAuthorizedExceptionNotification(notAuthorizedException);
            }
            catch (UserNotConfirmedException userNotConfirmedException)
            {
                AddUserNotConfirmedExceptionNotification(userNotConfirmedException);
            }
            catch (AmazonServiceException amazonServiceException)
            {
                AddAmazonServiceExceptionNotification(amazonServiceException);
            }
            catch (Exception exception)
            {
                AddGenericExceptionValidatorNotification(exception);
            }

            return new LoginResponseViewModel();
        }

        public async Task<bool> ResendConfirmationCode(ResendConfirmationCodeRequestViewModel resendConfirmationCodeViewModel)
        {
            try
            {
                var resendConfirmationCode = BuildMapper<ResendConfirmationCode>(resendConfirmationCodeViewModel);

                CheckAndRegisterInvalidNotifications(resendConfirmationCode);

                if (resendConfirmationCode.Invalid) return false;

                var user = await FindUserByNameAsync(resendConfirmationCode.UserName);

                ValidateUserNotFoundException(user, resendConfirmationCode.UserName);
                ValidateUserAlreadyConfirmedException(user, resendConfirmationCode.UserName);

                using (var identityProviderClient = IdentityProvider)
                    await identityProviderClient.ResendConfirmationCodeAsync(
                        BuildResendConfirmationCodeRequest(resendConfirmationCodeViewModel.UserName));

                return true;
            }
            catch (UserNotFoundException userNotFoundException)
            {
                AddUserNotFoundExceptionNotification(userNotFoundException);
            }
            catch (UserAlreadyConfirmedException userAlreadyConfirmedException)
            {
                AddUserAlreadyConfirmedExceptionNotification(userAlreadyConfirmedException);
            }
            catch (Exception exception)
            {
                AddGenericExceptionValidatorNotification(exception);
            }

            return false;
        }

        public async Task<bool> ForgotPassword(ForgotPasswordRequestViewModel forgotPasswordViewModel)
        {
            try
            {
                var forgotPassword = BuildMapper<ForgotPassword>(forgotPasswordViewModel);

                CheckAndRegisterInvalidNotifications(forgotPassword);

                if (forgotPassword.Invalid) return false;

                var user = await FindUserByNameAsync(forgotPassword.UserName);

                ValidateUserNotFoundException(user, forgotPassword.UserName);

                using (var identityProviderClient = IdentityProvider)
                    await identityProviderClient.ForgotPasswordAsync(BuildForgotPasswordRequest(forgotPassword.UserName));

                return true;
            }
            catch (UserNotFoundException userNotFoundException)
            {
                AddUserNotFoundExceptionNotification(userNotFoundException);
            }
            catch (Exception exception)
            {
                AddGenericExceptionValidatorNotification(exception);
            }

            return false;
        }

        public async Task<bool> ResetPassword(ResetPasswordRequestViewModel resetPasswordRequestViewModel)
        {
            try
            {
                var resetPassword = BuildMapper<ResetPassword>(resetPasswordRequestViewModel);

                CheckAndRegisterInvalidNotifications(resetPassword);

                if (resetPassword.Invalid) return false;

                var user = await FindUserByNameAsync(resetPassword.UserName);

                ValidateUserNotFoundException(user, resetPassword.UserName);

                using (var identityProviderClient = IdentityProvider)
                    await identityProviderClient.ConfirmForgotPasswordAsync(BuildConfirmForgotPasswordRequest(resetPassword));

                return true;
            }
            catch (UserNotFoundException userNotFoundException)
            {
                AddUserNotFoundExceptionNotification(userNotFoundException);
            }
            catch (Exception exception)
            {
                AddGenericExceptionValidatorNotification(exception);
            }

            return false;
        }

        private string BuildSecretHash(string userName)
        {
            return CognitoHashCalculatorHelper.GetSecretHash(userName,
                                _cloudConfigurationService.GetUserPoolClientId(),
                                _cloudConfigurationService.GetUserPoolClientSecret());
        }

        private void AddLoginParameters(LoginRequestViewModel loginViewModel)
        {
            LoginIdentityProviderRequest.AuthParameters["USERNAME"] = loginViewModel.UserName;
            LoginIdentityProviderRequest.AuthParameters["PASSWORD"] = loginViewModel.Password;
            LoginIdentityProviderRequest.AuthParameters["SECRET_HASH"] = BuildSecretHash(loginViewModel.UserName);
        }

        private void AddRefreshTokenParameters(RefreshTokenRequestViewModel refreshTokenViewModel)
        {
            RefreshTokenIdentityProviderRequest.AuthParameters["USERNAME"] = refreshTokenViewModel.UserName;
            RefreshTokenIdentityProviderRequest.AuthParameters["REFRESH_TOKEN"] = refreshTokenViewModel.Token;
            RefreshTokenIdentityProviderRequest.AuthParameters["SECRET_HASH"] = BuildSecretHash(refreshTokenViewModel.UserName);
        }

        private void AddSignUpParameters(SignUpRequest signUpRequest, SignUp signUp)
        {
            signUpRequest.UserAttributes.Add(new AttributeType() { Name = "name", Value = signUp.UserName });
            signUpRequest.UserAttributes.Add(new AttributeType() { Name = "email", Value = signUp.Email });
        }

        private void CheckAndRegisterInvalidNotifications(EntityBase entityBase)
        {
            if (entityBase.Invalid) _notificationContext.AddNotifications(entityBase.ValidationResult);
        }

        private async Task<CognitoUser> FindUserByNameAsync(string userName)
        {
            return await _userManager.FindByNameAsync(userName).ConfigureAwait(false);
        }

        private CognitoUser BuildUserObject(string userName)
        {
            return new CognitoUser(userName, _cloudConfigurationService.GetUserPoolClientId(), _userPool, IdentityProvider);
        }

        private void ValidateUserNotFoundException(CognitoUser user, string userName)
        {
            if (user == null) throw new UserNotFoundException($"The user {userName} was not found");
        }

        private void ValidateUserAlreadyConfirmedException(CognitoUser user, string userName)
        {
            if (!"UNCONFIRMED".Equals(user.Status)) throw new UserAlreadyConfirmedException($"The user {userName} is already confirmed");
        }

        private TModel BuildMapper<TModel>(object source)
        {
            return _mapper.Map<TModel>
                               (source, mapperOptions => mapperOptions
                                .AfterMap((_, instance) =>
                                {
                                    if (instance is EntityBase) ((EntityBase)instance).Validate(instance);
                                }));
        }

        private ForgotPasswordRequest BuildForgotPasswordRequest(string userName)
        {
            return new ForgotPasswordRequest()
            {
                ClientId = _cloudConfigurationService.GetUserPoolClientId(),
                Username = userName,
                SecretHash = BuildSecretHash(userName)
            };
        }

        private ResendConfirmationCodeRequest BuildResendConfirmationCodeRequest(string userName)
        {
            return new ResendConfirmationCodeRequest()
            {
                ClientId = _cloudConfigurationService.GetUserPoolClientId(),
                Username = userName,
                SecretHash = BuildSecretHash(userName)
            };
        }

        private ConfirmForgotPasswordRequest BuildConfirmForgotPasswordRequest(ResetPassword resetPassword)
        {
            return new ConfirmForgotPasswordRequest()
            {
                ClientId = _cloudConfigurationService.GetUserPoolClientId(),
                Username = resetPassword.UserName,
                ConfirmationCode = resetPassword.Code,
                Password = resetPassword.Password,
                SecretHash = BuildSecretHash(resetPassword.UserName)
            };
        }

        private SignUpRequest BuildSignUpRequest(SignUp signUp)
        {
            var signUpRequest = new SignUpRequest
            {
                ClientId = _cloudConfigurationService.GetUserPoolClientId(),
                SecretHash = BuildSecretHash(signUp.UserName),
                Username = signUp.UserName,
                Password = signUp.Password,
            };

            AddSignUpParameters(signUpRequest, signUp);

            return signUpRequest;
        }

        private ConfirmSignUpRequest BuildConfirmSignUpRequest(ConfirmSignUp confirmSignUp)
        {
            var confirmSignUpRequest = new ConfirmSignUpRequest
            {
                ClientId = _cloudConfigurationService.GetUserPoolClientId(),
                SecretHash = BuildSecretHash(confirmSignUp.UserName),
                Username = confirmSignUp.UserName,
                ConfirmationCode = confirmSignUp.Code
            };

            return confirmSignUpRequest;
        }

        private AdminDeleteUserRequest BuildAdminDeleteUserRequest(ChangePassword changePassword)
        {
            return new AdminDeleteUserRequest() { Username = changePassword.UserName, UserPoolId = _userPool.PoolID };
        }

        private AdminDeleteUserRequest BuildAdminDeleteUserRequest(ChangeEmail changeEmail)
        {
            return new AdminDeleteUserRequest() { Username = changeEmail.UserName, UserPoolId = _userPool.PoolID };
        }

        private void AddUsernameExistsExceptionNotification(UsernameExistsException usernameExistsException)
        {
            _notificationContext.AddNotification("UsernameExistsExceptionValidator", usernameExistsException.Message);
            _logger.LogInformation($"UsernameExistsExceptionValidator: {usernameExistsException.Message}");
        }

        private void AddUserNotFoundExceptionNotification(UserNotFoundException userNotFoundException)
        {
            _notificationContext.AddNotification("UserNotFoundExceptionValidator", userNotFoundException.Message);
            _logger.LogInformation($"UserNotFoundExceptionValidator: {userNotFoundException.Message}");
        }

        private void AddUserAlreadyConfirmedExceptionNotification(UserAlreadyConfirmedException userAlreadyConfirmedException)
        {
            _notificationContext.AddNotification("UserAlreadyConfirmedExceptionValidator", userAlreadyConfirmedException.Message);
            _logger.LogInformation($"UserAlreadyConfirmedExceptionValidator: {userAlreadyConfirmedException.Message}");
        }

        private void AddNotAuthorizedExceptionNotification(NotAuthorizedException notAuthorizedException)
        {
            _notificationContext.AddNotification("NotAuthorizedValidator", notAuthorizedException.Message);
            _logger.LogInformation($"NotAuthorizedValidator: {notAuthorizedException.Message}");
        }

        private void AddUserNotConfirmedExceptionNotification(UserNotConfirmedException userNotConfirmedException)
        {
            _notificationContext.AddNotification("UserNotConfirmedExceptionValidator", userNotConfirmedException.Message);
            _logger.LogInformation($"UserNotConfirmedExceptionValidator: {userNotConfirmedException.Message}");
        }

        private void AddAmazonServiceExceptionNotification(AmazonServiceException amazonServiceException)
        {
            _notificationContext.AddNotification("ServiceExceptionValidator", amazonServiceException.Message);
            _logger.LogError($"ServiceExceptionValidator: {amazonServiceException.Message}");
        }

        private void AddGenericExceptionValidatorNotification(Exception genericException)
        {
            _notificationContext.AddNotification("GenericExceptionValidator", genericException.Message);
            _logger.LogError($"GenericExceptionValidator: {genericException.Message}");
        }
    }
}