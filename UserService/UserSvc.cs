using ActivityService;
using CookieService;
using DataService;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModelService;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserService
{
    public class UserSvc: IUserSvc
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IHostingEnvironment _env;
        private readonly ApplicationDbContext _db;
        private readonly ICookieSvc _cookieSvc;
        private readonly IActivitySvc _activitySvc;
        private readonly IServiceProvider _provider;
        private readonly DataProtectionKeys _dataProtectionKeys;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserSvc(
                    UserManager<ApplicationUser> userManager,
                    IHostingEnvironment env,
                    ApplicationDbContext db,
                    ICookieSvc cookieSvc,
                    IActivitySvc activitySvc,
                    IServiceProvider provider,
                    IOptions<DataProtectionKeys> dataProtectionKeys,
                    IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _env = env;
            _db = db;
            _cookieSvc = cookieSvc;
            _activitySvc = activitySvc;
            _dataProtectionKeys = dataProtectionKeys.Value;
            _provider = provider;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<ProfileModel> GetUserProfileByIdAsync(string userId)
        {
            ProfileModel userProfile = new ProfileModel();

            var loggedInUserId = GetLoggedInUserId();
            var user = await _userManager.FindByIdAsync(loggedInUserId);

            if (user == null || user.Id != userId) return null;

            try
            {
                userProfile = new ProfileModel()
                {
                    UserId = user.Id,
                    Email = user.Email,
                    Username = user.UserName,
                    Phone = user.PhoneNumber,
                    Birthday = user.Birthday,
                    Gender = user.Gender,
                    Displayname = user.DisplayName,
                    Firstname = user.Firstname,
                    Middlename = user.Middlename,
                    Lastname = user.Lastname,
                    IsEmailVerified = user.EmailConfirmed,
                    IsPhoneVerified = user.PhoneNumberConfirmed,
                    IsTermsAccepted = user.Terms,
                    IsTwoFactorOn = user.TwoFactorEnabled,
                    ProfilePic = user.ProfilePic,
                    UserRole = user.UserRole,
                    IsAccountLocked = user.LockoutEnabled,
                    IsEmployee = user.IsEmployee,
                    UseAddress = new List<AddressModel>(await _db.Addresses.Where(x => x.UserId == user.Id).Select(n =>
                        new AddressModel()
                        {
                            AddressId = n.AddressId,
                            Line1 = n.Line1,
                            Line2 = n.Line2,
                            Unit = n.Unit,
                            Country = n.Country,
                            State = n.State,
                            City = n.City,
                            PostalCode = n.PostalCode,
                            Type = n.Type,
                            UserId = n.UserId
                        }).ToListAsync()),
                    Activities = new List<ActivityModel>(_db.Activities.Where(x => x.UserId == user.Id)).OrderByDescending(o => o.Date).Take(20).ToList()
                };
            }
            catch (Exception ex)
            {
                Log.Error("An error occurred in GetUserProfileByIdAsync {Error} {StackTrace} {InnerException} {Source}",
                                 ex.Message, ex.StackTrace, ex.InnerException, ex.Source);
            }

            return userProfile;
        }

        private string GetLoggedInUserId()
        {
            try
            {
                var protectorProvider = _provider.GetService<IDataProtectionProvider>();
                var protector = protectorProvider.CreateProtector(_dataProtectionKeys.ApplicationUserKey);
                var unprotectUserId = protector.Unprotect(_cookieSvc.Get("user_id"));
                return unprotectUserId;
            }
            catch (Exception ex)
            {
                Log.Error("An error occured in GetLoggedInUserId {Error} {StackTrace} {InnerException} {Source}",
                    ex.Message, ex.StackTrace, ex.InnerException, ex.Source);
            }
            return null;
        }
    }
}
