using ModelService;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace AuthService
{
    public interface IAuthSvc
    {
        Task<TokenResponseModel> Auth(LoginViewModel model);
    }
}
