namespace Swapcode.AlloyWeb.Business.Claims
{
    /// <summary>
    /// Contains constants for security group names (or permissions that can be used as users roles).
    /// </summary>
    internal static class PermissionGroupNames
    {
        /// <summary>
        /// Presents a group that will have administrative rights on the cms.
        /// </summary>
        public const string WebSiteSuperUser = "PERM_CMS_SUPERUSER";
        /// <summary>
        /// Presents a group that will have content editing rights on the cms.
        /// </summary>
        public const string WebSiteEditor = "PERM_CMS_EDITOR";
        /// <summary>
        /// Presents a group that will have only read access rights to cms.
        /// </summary>
        public const string WebSiteReader = "PERM_CMS_READER";
    }
}