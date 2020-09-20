using Microsoft.EntityFrameworkCore.Internal;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using FunctionalService;

namespace DataService
{
    public static class DbContextInitializer
    {
        public static async Task Initialize(
            DataProtectionKeysContext dataProtectionKeysContext, 
            ApplicationDbContext applicationDbContext,
            IFunctionalSvc functionalSvc)
        {
            await dataProtectionKeysContext.Database.EnsureCreatedAsync();
            await applicationDbContext.Database.EnsureCreatedAsync();

            if (applicationDbContext.ApplicationUsers.Any())
            {
                return;
            }

            await functionalSvc.CreateDefaultAdminUser();
            await functionalSvc.CreateDefaultUser();
        }
    }
}
