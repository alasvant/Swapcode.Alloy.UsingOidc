using System;
using System.Web.Mvc;

namespace Swapcode.AlloyWeb
{
    public class EPiServerApplication : EPiServer.Global
    {
        protected void Application_Start()
        {
            // Edited: Added disabling of MVC version header
            // Disable X-AspNetMvc-Version header (for security ;-) security audits will mention otherwise of this)
            MvcHandler.DisableMvcResponseHeader = true;

            AreaRegistration.RegisterAllAreas();
        }
    }
}