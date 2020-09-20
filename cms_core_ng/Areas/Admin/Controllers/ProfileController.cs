using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CookieService;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using ModelService;
using UserService;

namespace CMS_CORE_NG.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class ProfileController : Controller
    {
        private readonly ICookieSvc _cookieSvc;
        private readonly IServiceProvider _provider;
        private readonly DataProtectionKeys _dataProtectionKeys;
        private readonly AppSettings _appSettings;
        private readonly IUserSvc _userSvc;
        private static AdminBaseViewModel _adminBaseViewModel;

        public ProfileController(
                IUserSvc userSvc,
                ICookieSvc cookieSvc,
                IServiceProvider provider,
                IOptions<DataProtectionKeys> dataProtectionKeys,
                IOptions<AppSettings> appSettings)
        {
            _userSvc = userSvc;
            _cookieSvc = cookieSvc;
            _provider = provider;
            _dataProtectionKeys = dataProtectionKeys.Value;
            _appSettings = appSettings.Value;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Security()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Activity()
        {
            return View();
        }

        private async Task SetAdminBaseViewModel()
        {
            var protectorProvider = _provider.GetService<IDataProtectionProvider>();
            var protector = protectorProvider.CreateProtector(_dataProtectionKeys.ApplicationUserKey);
            var userProfile = await _userSvc.GetUserProfileByIdAsync(protector.Unprotect(_cookieSvc.Get("user_id")));
            var resetPassword = new ResetPasswordViewModel();

            _adminBaseViewModel = new AdminBaseViewModel
            {
                Profile = userProfile,
                AddUser = null,
                AppSetting = null,
                Dashboard = null,
                ResetPassword = resetPassword,
                SiteWideSetting = null
            };
        }
    }
}
