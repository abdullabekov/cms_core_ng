using Microsoft.EntityFrameworkCore.Internal;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using FunctionalService;
using CountryService;

namespace DataService
{
    public static class DbContextInitializer
    {
        public static async Task Initialize(
            DataProtectionKeysContext dataProtectionKeysContext, 
            ApplicationDbContext applicationDbContext,
            IFunctionalSvc functionalSvc,
            ICountrySvc countrySvc)
        {
            await dataProtectionKeysContext.Database.EnsureCreatedAsync();
            await applicationDbContext.Database.EnsureCreatedAsync();

            if (applicationDbContext.ApplicationUsers.Any())
            {
                return;
            }

            // If empty create Admin User and App User
            await functionalSvc.CreateDefaultAdminUser();
            await functionalSvc.CreateDefaultUser();

            // Populate Country database
            var countries = await countrySvc.GetCountriesAsync();
            if (countries.Count > 0)
            {
                await applicationDbContext.Countries.AddRangeAsync(countries);
                await applicationDbContext.SaveChangesAsync();
            }
        }
    }
}
