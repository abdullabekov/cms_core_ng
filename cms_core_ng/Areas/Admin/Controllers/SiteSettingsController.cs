using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace CMS_CORE_NG.Areas.Admin.Controllers
{
    public class SiteSettingsController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
