namespace Swapcode.AlloyWeb.Business.Claims
{
    /// <summary>
    /// Episerver role constants.
    /// </summary>
    internal static class EpiRoles
    {
        /// <summary>
        /// Has access to admin view.
        /// </summary>
        public const string Admin = "WebAdmins";
        /// <summary>
        /// Has access to edit view.
        /// </summary>
        public const string Editor = "WebEditors";
        /// <summary>
        /// Can publish content.
        /// </summary>
        public const string Publisher = "SitePublishers";
    }
}