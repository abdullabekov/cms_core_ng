using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace ModelService
{
    public class ResponseStatusInfoModel
    {
        public string Message { get; set; }

        public HttpStatusCode StatusCode { get; set; }
    }
}
