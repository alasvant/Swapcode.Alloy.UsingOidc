namespace Swapcode.AlloyWeb.Business.Claims
{
    /// <summary>
    /// Contains custom identity resource names.
    /// </summary>
    internal static class CustomScopeNames
    {
        /// <summary>
        /// Name of identity resource name that will contain users security groups (like roles).
        ///  This is just to demonstrate real world cases where the identity provider might not use the "role" name for these claims.
        /// </summary>
        public const string Permissions = "PERMGROUP_USER";
        /// <summary>
        /// Demo identity resource that returns profile and PermissionGroupIdentityResourceName claims.
        /// </summary>
        public const string ProfileWithPermissions = "PROFILEWITHPERMGROUPUSER";
        /// <summary>
        /// Demo identity resource that returns user membership status claims.
        /// </summary>
        public const string MembershipStatus = "MEMBER_USER";
    }
}