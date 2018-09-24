using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Swapcode.AlloyWeb.Business.Claims
{
    /// <summary>
    /// Claims related extensions.
    /// </summary>
    internal static class ClaimExtensions
    {
        /// <summary>
        /// Gets the value of first matched claim.
        /// </summary>
        /// <param name="claims">claims</param>
        /// <param name="claimType">claim type which value to get</param>
        /// <returns>null or the claim value</returns>
        internal static string GetClaimValue(this IEnumerable<Claim> claims, string claimType)
        {
            if (claims == null || string.IsNullOrWhiteSpace(claimType))
            {
                return null;
            }

            return claims.FirstOrDefault(c => string.Compare(c.Type, claimType, StringComparison.OrdinalIgnoreCase) == 0)?.Value;
        }

        /// <summary>
        /// Adds claim with given type to <paramref name="identity"/> claims collection if the source contains claim with <paramref name="sourceClaimType"/>.
        /// </summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="claimType">destination claim type</param>
        /// <param name="source">source claims</param>
        /// <param name="sourceClaimType">source claim type</param>
        internal static void AddClaimFromSource(this ClaimsIdentity identity, string claimType, IEnumerable<Claim> source, string sourceClaimType)
        {
            if (identity != null && !string.IsNullOrWhiteSpace(claimType))
            {
                string valueToAdd = source.GetClaimValue(sourceClaimType);

                if (!string.IsNullOrWhiteSpace(valueToAdd))
                {
                    identity.AddClaim(new Claim(claimType, valueToAdd));
                }
            }
        }
    }
}