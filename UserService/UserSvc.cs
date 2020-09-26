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
using System.IO;
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

        public async Task<ProfileModel> GetUserProfileByUsernameAsync(string username)
        {
            var userProfile = new ProfileModel();

            try
            {
                var loggedInUserId = GetLoggedInUserId();
                var user = await _userManager.FindByIdAsync(loggedInUserId);
                if (user == null || user.UserName != username) return null;

                userProfile = await GetUserProfileByIdAsync(user.Id);
            }
            catch (Exception ex)
            {
                Log.Error("An error occurred in GetUserProfileByUsernameAsync {Error} {StackTrace} {InnerException} {Source}",
                    ex.Message, ex.StackTrace, ex.InnerException, ex.Source);
            }

            return userProfile;
        }

        public async Task<ProfileModel> GetUserProfileByEmailAsync(string email)
        {
            var userProfile = new ProfileModel();

            try
            {
                var loggedInUserId = GetLoggedInUserId();
                var user = await _userManager.FindByIdAsync(loggedInUserId);
                if (user == null || user.Email != email) return null;

                userProfile = await GetUserProfileByIdAsync(user.Id);
            }
            catch (Exception ex)
            {
                Log.Error("An error occurred in GetUserProfileByUsernameAsync {Error} {StackTrace} {InnerException} {Source}",
                    ex.Message, ex.StackTrace, ex.InnerException, ex.Source);
            }

            return userProfile;
        }

        public async Task<bool> CheckPasswordAsync(ProfileModel model, string password)
        {
            try
            {
                var loggedUserId = GetLoggedInUserId();
                var user = await _userManager.FindByIdAsync(loggedUserId);

                if (user.UserName != _cookieSvc.Get("username") ||
                    user.UserName != model.Username)
                {
                    return false;
                }                    

                if (!await _userManager.CheckPasswordAsync(user, password))
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Log.Error("An error occurred in CheckPasswordAsync {Error} {StackTrace} {InnerException} {Source}",
                    ex.Message, ex.StackTrace, ex.InnerException, ex.Source);
            }
            return true;
        }

        public async Task<bool> UpdateProfileAsync(IFormCollection formData)
        {
            var loggedInUserId = GetLoggedInUserId();
            var user = await _userManager.FindByIdAsync(loggedInUserId);

            if (user == null) return false;

            if (user.UserName != _cookieSvc.Get("username") ||
                user.UserName != formData["username"].ToString() ||
                user.Email != formData["email"].ToString())
                return false;

            try
            {
                ActivityModel activityModel = new ActivityModel { UserId = user.Id };
                await UpdateProfilePicAsync(formData, user);

                user.Firstname = formData["firstname"];
                user.Birthday = formData["birthdate"];
                user.Lastname = formData["lastname"];
                user.Middlename = formData["middlename"];
                user.DisplayName = formData["displayname"];
                user.PhoneNumber = formData["phone"];
                user.Gender = formData["gender"];
                user.TwoFactorEnabled = Convert.ToBoolean(formData["IsTwoFactorOn"]);

                /* If Addresses exist we update them => If Addresses do not exist we add them */
                await InsertOrUpdateAddress(user.Id, "Shipping", formData["saddress1"], formData["saddress2"], formData["scountry"], formData["sstate"], formData["scity"], formData["spostalcode"], formData["sunit"]);
                await InsertOrUpdateAddress(user.Id, "Billing", formData["address1"], formData["address2"], formData["country"], formData["state"], formData["city"], formData["postalcode"], formData["unit"]);

                await _userManager.UpdateAsync(user);

                activityModel.Date = DateTime.UtcNow;
                activityModel.IpAddress = _cookieSvc.GetUserIP();
                activityModel.Location = _cookieSvc.GetUserCountry();
                activityModel.OperatingSystem = _cookieSvc.GetUserOS();
                activityModel.Type = "Profile update successful";
                activityModel.Icon = "fas fa-thumbs-up";
                activityModel.Color = "success";
                await _activitySvc.AddUserActivity(activityModel);

                return true;
            }
            catch (Exception ex)
            {
                Log.Error("An error occurred while updating profile {Error} {StackTrace} {InnerException} {Source}",
                    ex.Message, ex.StackTrace, ex.InnerException, ex.Source);
            }
            return false;
        }


        public async Task<bool> AddUserActivity(ActivityModel model)
        {
            try
            {
                await _activitySvc.AddUserActivity(model);
                return true;
            }
            catch (Exception ex)
            {
                Log.Error("An error occurred while seeding the database  {Error} {StackTrace} {InnerException} {Source}",
                    ex.Message, ex.StackTrace, ex.InnerException, ex.Source);
            }

            return false;
        }

        public async Task<bool> ChangePasswordAsync(ProfileModel model, string newPassword)
        {
            bool result;
            try
            {
                ActivityModel activityModel = new ActivityModel();
                activityModel.Date = DateTime.UtcNow;
                activityModel.IpAddress = _cookieSvc.GetUserIP();
                activityModel.Location = _cookieSvc.GetUserCountry();
                activityModel.OperatingSystem = _cookieSvc.GetUserOS();

                var loggedInUserId = GetLoggedInUserId();
                var user = await _userManager.FindByIdAsync(loggedInUserId);

                if (user != null)
                {
                    user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, newPassword);
                    var updateResult = await _userManager.UpdateAsync(user);
                    result = updateResult.Succeeded;
                    activityModel.UserId = user.Id;
                    activityModel.Type = "Password Changed successful";
                    activityModel.Icon = "fas fa-thumbs-up";
                    activityModel.Color = "success";
                    await _activitySvc.AddUserActivity(activityModel);
                }
                else
                {
                    result = false;
                }

            }
            catch (Exception ex)
            {
                result = false;
                Log.Error("An error occurred while seeding the database  {Error} {StackTrace} {InnerException} {Source}",
                    ex.Message, ex.StackTrace, ex.InnerException, ex.Source);
            }

            return result;
        }

        public async Task<List<ActivityModel>> GetUserActivity(string username)
        {
            List<ActivityModel> userActivities = new List<ActivityModel>();

            try
            {
                var loggedInUserId = GetLoggedInUserId();
                var user = await _userManager.FindByIdAsync(loggedInUserId);

                if (user == null || user.UserName != username) return null;

                userActivities = await _db.Activities.Where(x => x.UserId == user.Id).OrderByDescending(o => o.Date).Take(20).ToListAsync();
            }
            catch (Exception ex)
            {
                Log.Error("An error occurred while seeding the database  {Error} {StackTrace} {InnerException} {Source}",
                    ex.Message, ex.StackTrace, ex.InnerException, ex.Source);
            }

            return userActivities;
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

        private async Task<ApplicationUser> UpdateProfilePicAsync(IFormCollection formData, ApplicationUser user)
        {
            // First we create an empty array to store old file info
            var oldProfilePic = new string[1];
            // we will store path of old file to delete in an empty array.
            oldProfilePic[0] = Path.Combine(_env.WebRootPath + user.ProfilePic);

            // Create the Profile Image Path
            var profPicPath = _env.WebRootPath + $"{Path.DirectorySeparatorChar}uploads{Path.DirectorySeparatorChar}user{Path.DirectorySeparatorChar}profile{Path.DirectorySeparatorChar}";

            // If we have received any files for update, then we update the file path after saving to server
            // else we return the user without any changes
            if (formData.Files.Count <= 0) return user;

            var extension = Path.GetExtension(formData.Files[0].FileName);
            var filename = DateTime.Now.ToString("yymmssfff");
            var path = Path.Combine(profPicPath, filename) + extension;
            var dbImagePath = Path.Combine($"{Path.DirectorySeparatorChar}uploads{Path.DirectorySeparatorChar}user{Path.DirectorySeparatorChar}profile{Path.DirectorySeparatorChar}", filename) + extension;

            user.ProfilePic = dbImagePath;

            // Copying New Files to the Server - profile Folder
            await using (var stream = new FileStream(path, FileMode.Create))
            {
                await formData.Files[0].CopyToAsync(stream);
            }

            // Delete old file after successful update
            if (!File.Exists(oldProfilePic[0])) return user;

            File.SetAttributes(oldProfilePic[0], FileAttributes.Normal);
            File.Delete(oldProfilePic[0]);

            return user;
        }

        private async Task InsertOrUpdateAddress(string userId, string type, string line1, string line2, string country,
            string state, string city, string postalcode, string unit)
        {
            var updateAddress = _db.Addresses.FirstOrDefault(ad => ad.User.Id == userId && ad.Type == type);
            await using var dbContextTransaction = await _db.Database.BeginTransactionAsync();
            try
            {
                var newAddress = new AddressModel();
                if (updateAddress != null)
                {
                    updateAddress.Line1 = line1;
                    updateAddress.Line2 = line2;
                    updateAddress.Country = country;
                    updateAddress.City = city;
                    updateAddress.State = state;
                    updateAddress.PostalCode = postalcode;
                    updateAddress.Unit = unit;
                    _db.Entry(updateAddress).State = EntityState.Modified;
                }
                else
                {
                    newAddress.Line1 = line1;
                    newAddress.Line2 = line2;
                    newAddress.Country = country;
                    newAddress.City = city;
                    newAddress.State = state;
                    newAddress.PostalCode = postalcode;
                    newAddress.Unit = unit;
                    _db.Entry(newAddress).State = EntityState.Added;
                }

                await _db.SaveChangesAsync();

                await dbContextTransaction.CommitAsync();
            }
            catch (Exception ex)
            {
                await dbContextTransaction.RollbackAsync();

                Log.Error("An error occurred while seeding the database  {Error} {StackTrace} {InnerException} {Source}",
                    ex.Message, ex.StackTrace, ex.InnerException, ex.Source);
            }
        }
    }
}
