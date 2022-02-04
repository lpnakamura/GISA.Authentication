using GISA.Authentication.Application.Notifications;
using Microsoft.AspNetCore.Mvc;

namespace GISA.Authentication.WebApi.Controllers
{
    [Produces("application/json")]
    public abstract class ApiBaseController : ControllerBase
    {
        private readonly NotificationContext _notificationContext;

        public ApiBaseController(NotificationContext notificationContext)
        {
            this._notificationContext = notificationContext;
        }

        protected ActionResult CustomResponse(ActionResult actionResult)
        {
            if (!this._notificationContext.HasNotifications) return actionResult;
            return BadRequest(this._notificationContext.Notifications);
        }

        protected ActionResult CustomResponse()
        {
            return this.CustomResponse(Ok());
        }
    }
}