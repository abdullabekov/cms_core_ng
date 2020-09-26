using Microsoft.AspNetCore.Http;
using ModelService;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace UserService
{
    public interface IUserSvc
    {
        Task<ProfileModel> GetUserProfileByIdAsync(string userId);
        Task<ProfileModel> GetUserProfileByUsernameAsync(string username);
        Task<ProfileModel> GetUserProfileByEmailAsync(string email);
        Task<bool> CheckPasswordAsync(ProfileModel model, string password);
        Task<bool> UpdateProfileAsync(IFormCollection formData);
        Task<bool> AddUserActivity(ActivityModel model);
        Task<bool> ChangePasswordAsync(ProfileModel model, string newPassword);
        Task<List<ActivityModel>> GetUserActivity(string username);
    }
}
