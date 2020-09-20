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
    }
}
