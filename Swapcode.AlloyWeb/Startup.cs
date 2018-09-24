using EPiServer.Logging;
using EPiServer.Security;
using EPiServer.ServiceLocation;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Swapcode.AlloyWeb.Business.Claims;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web.Helpers;

// this is needed by OWIN to know what class is your OWIN startup class
[assembly: OwinStartup(typeof(Swapcode.AlloyWeb.Startup))]

namespace Swapcode.AlloyWeb
{
    /// <summary>
    /// Our OWIN startup class. OWIN will call the Configuration method to configure/build the pipeline.
    /// </summary>
    public class Startup
    {
        /// <summary>
        /// Shared logger (in real app you want to have a separate logger for all the authentication and authorization logging)
        ///  Meaning that you most likely would request a named logger where only goes the authentication related messages.
        /// </summary>
        private static readonly ILogger Logger = LogManager.GetLogger(typeof(Startup));

        public void Configuration(IAppBuilder app)
        {
            // Show PII information in log entries (in real app this setting should come from your app configuration source)
            // when you set this to true, you will see more details about an exception, like if the signature validation fails
            // you will see the information what key identifier was used to validate the signature of a token (otherwise you see message about PII info removed)
            // PII means: personally identifiable information
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;

            // clear the default mappings so that framework doesn't try to automatically map claims for us using its defaults
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            // Antiforgery requires this mapping/information or otherwise we will get the following error for example when trying to access visitor groups
            // A claim of type 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier' or 'http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider' was not present on the provided ClaimsIdentity.
            // We could add those claim(s) to the user or directly configure the AntiForgeryConfig.UniqueClaimTypeIdentifier
            // here we set that antiforgery should use the 'CustomClaimNames.EpiUsername' claim value which is unique for each user in this demo
            AntiForgeryConfig.UniqueClaimTypeIdentifier = CustomClaimNames.EpiUsername; // this could be also JwtClaimTypes.Subject but then you need to remember to add that claim to the claimsidentity

            // this is not required but if you have issues with cookies then add Nuget package: Kentor.OwinCookieSaver
            // to see if that sorts out your cookie issue
            // NuGet : https://www.nuget.org/packages/Kentor.OwinCookieSaver/
            // GitHub : https://github.com/Sustainsys/owin-cookie-saver
            //app.UseKentorOwinCookieSaver();

            // set the default authentication type to 'Cookies'
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            // set the cookie auth options
            // the cookies is valid for 'configuration value here' minutes and uses sliding expiration, meaning framework will extend the validty automatically
            // see: https://docs.microsoft.com/en-us/dotnet/api/system.web.security.formsauthentication.slidingexpiration?view=netframework-4.7.2
            // the OpenIdConnectAuthenticationOptions.UseTokenLifetime has to be false for this to work, if the value is true then the token lifetime will be used which is usually very short time
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                ExpireTimeSpan = TimeSpan.FromMinutes(OIDCInMemoryConfiguration.AuthCookieValidMinutes),
                SlidingExpiration = true
            });

            // Configure the OIDC auth options
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = OIDCInMemoryConfiguration.ClientId,
                ClientSecret = OIDCInMemoryConfiguration.ClientSecret,
                Authority = OIDCInMemoryConfiguration.Authority, // this should be set so that the middleware will use OIDC discovery to automatically setup endpoint configurations
                RedirectUri = OIDCInMemoryConfiguration.WebAppOidcEndpoint, // allowed URL to return tokens or authorization codes to, must match what has been defined for client in identity provider
                PostLogoutRedirectUri = OIDCInMemoryConfiguration.PostLogoutRedirectUrl, // allowed URL where client is allowed to be redirected after IdP logout
                Scope = $"openid email {CustomScopeNames.ProfileWithPermissions} {CustomScopeNames.MembershipStatus}", // TODO: add "offline_access" scope if you need refreshtoken
                ResponseType = "code id_token", // hybrid flow
                RequireHttpsMetadata = OIDCInMemoryConfiguration.RequireHttpsMetadata,
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = JwtClaimTypes.Name, // change name claim name to match our demo IdP returned claim name
                    RoleClaimType = CustomClaimNames.Permission, // change role claim name to match our demo IdP returned claim name
                    ValidateTokenReplay = true
                },
                SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType, // somewhere stated that needs to be after TokenValidationParameters
                UseTokenLifetime = false, // if this is true then the token life time is used (for example IdentityServer token lifetime is 5 minutes by default) for cookie auth lifetime
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = notification =>
                    {
                        // if single site setup, the redirect url is automatically set to the page you were trying to access
                        // For example in multi-tenant setup you want to change the return url here based on the current site address
                        // See Episerver sample: https://world.episerver.com/documentation/developer-guides/CMS/security/integrate-azure-ad-using-openid-connect/
                        // and the method: HandleMultiSitereturnUrl
                        //context.ProtocolMessage.RedirectUri = "http://host-of-your-site2/the-return-page/path/here/";

                        // what kind of message are we processing
                        switch (notification.ProtocolMessage.RequestType)
                        {
                            case OpenIdConnectRequestType.Authentication:

                                if (notification.OwinContext.Response.StatusCode == 401)
                                {
                                    // if the request is ajax request, like Episerver Dojo framework, don't try to redirect
                                    // but return 401 so the UI will properly display the login dialog
                                    if (IsAjaxRequest(notification.Request))
                                    {
                                        if (Logger.IsInformationEnabled())
                                        {
                                            Logger.Information($"Request is made with AJAX and response is 401.");
                                        }

                                        notification.HandleResponse();
                                        return Task.FromResult(0);
                                    }

                                    // To avoid a redirect loop to the IdP server send 403 when user is authenticated but does not have access
                                    if (notification.OwinContext.Authentication.User.Identity.IsAuthenticated)
                                    {
                                        if (Logger.IsInformationEnabled())
                                        {
                                            Logger.Information($"Request response code would be 401 but user '{notification.OwinContext.Authentication.User.Identity.Name}' is authenticated, switching response code to 403 (forbidden).");
                                        }

                                        notification.OwinContext.Response.StatusCode = 403;
                                        notification.HandleResponse();
                                        return Task.FromResult(0);
                                    }
                                }

                                break;
                            case OpenIdConnectRequestType.Logout:
                                // If signing out, add the id_token_hint if present
                                // see: http://openid.net/specs/openid-connect-session-1_0.html#rfc.section.5

                                if (notification.OwinContext.Authentication.User.Identity.IsAuthenticated)
                                {
                                    Logger.Information($"User is logging out. User: {notification.OwinContext.Authentication.User.Identity.Name}.");
                                }

                                var idTokenHint = notification.OwinContext.Authentication.User.FindFirst(OpenIdConnectParameterNames.IdToken);

                                if (idTokenHint != null)
                                {
                                    if (Logger.IsDebugEnabled())
                                    {
                                        Logger.Debug($"Redirecting to Identity provider for logout with IdTokenHint.");
                                    }

                                    notification.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                                }
                                else
                                {
                                    if (Logger.IsDebugEnabled())
                                    {
                                        Logger.Debug($"Redirecting to Identity provider for logout without IdTokenHint.");
                                    }
                                }

                                return Task.FromResult(0);

                            case OpenIdConnectRequestType.Token:
                                // nothing here :D
                                break;
                            default:
                                break;
                        }

                        return Task.FromResult(0);
                    },
                    AuthorizationCodeReceived = async notification =>
                    {
                        // show info about the claims if debug logging is enabled
                        if (Logger.IsDebugEnabled())
                        {
                            Logger.Debug($"Authorization code received for sub: {notification.JwtSecurityToken.Subject}. Received claims: {GetClaimsAsString(notification.JwtSecurityToken.Claims)}.");
                        }
                        else
                        {
                            Logger.Information($"Authorization code received for sub: {notification.JwtSecurityToken.Subject}.");
                        }

                        // config has been automatically setup using OIDC discovery because we have set the Authority value previously in when configuring OpenIdConnectAuthenticationOptions
                        OpenIdConnectConfiguration configuration = null;

                        try
                        {
                            // get OpenIdConnectConfiguration
                            configuration = await notification.Options.ConfigurationManager.GetConfigurationAsync(notification.Request.CallCancelled);
                        }
                        catch (Exception ex)
                        {
                            Logger.Error($"Failed to get OpenIdConnectConfiguration. Cannot authorize the client with sub: {notification.JwtSecurityToken.Subject}.", ex);
                            throw;
                        }

                        // configure token client, endpoint is automatically configured using the Auto discovery: /.well-known/openid-configuration
                        var tokenClient = new TokenClient(configuration.TokenEndpoint, notification.Options.ClientId, notification.Options.ClientSecret, style: AuthenticationStyle.PostValues);

                        // exchange the authorization 'code' to access token
                        var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(notification.ProtocolMessage.Code, notification.RedirectUri, cancellationToken: notification.Request.CallCancelled);

                        // check if there was an error fetching the acces token
                        if (tokenResponse.IsError)
                        {
                            Logger.Error($"There was an error retrieving the access token for sub: {notification.JwtSecurityToken.Subject}. Error: {tokenResponse.Error}. Error description: {tokenResponse.ErrorDescription}.");

                            notification.HandleResponse();

                            // TODO : redirect to friendly error page
                            // does 302 redirect, but SEO is not your concern here
                            // notification.Response.Redirect("/your/nice/error/page/address/here/");

                            notification.Response.Write($"Error retrieving access token. {tokenResponse.ErrorDescription}.");
                            return;
                        }

                        if (string.IsNullOrWhiteSpace(tokenResponse.AccessToken))
                        {
                            Logger.Error($"Didn't receive access token for sub: {notification.JwtSecurityToken.Subject}.");

                            notification.HandleResponse();

                            // TODO : redirect to friendly error page
                            // does 302 redirect, but SEO is not your concern here
                            // notification.Response.Redirect("/your/nice/error/page/address/here/");

                            notification.Response.Write($"Error, access token not received. {tokenResponse.ErrorDescription}.");
                            return;
                        }

                        // sub and iss claims musta have same value when using hybrid flow (in the id token and tokenresponse)
                        // http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2 3.3.3.6 ID Token
                        // If an ID Token is returned from both the Authorization Endpoint and from the Token Endpoint,
                        // which is the case for the response_type values "code id_token" and "code id_token token", the iss and sub Claim Values MUST be identical in both ID Tokens.

                        if (!string.IsNullOrWhiteSpace(tokenResponse.IdentityToken))
                        {
                            try
                            {
                                JwtSecurityTokenHandler idTokenHandler = new JwtSecurityTokenHandler();
                                var parsedIdToken = idTokenHandler.ReadJwtToken(tokenResponse.IdentityToken);

                                if (string.Compare(parsedIdToken.Issuer, notification.JwtSecurityToken.Issuer, StringComparison.OrdinalIgnoreCase) != 0 ||
                                    string.Compare(parsedIdToken.Subject, notification.JwtSecurityToken.Subject, StringComparison.OrdinalIgnoreCase) != 0)
                                {
                                    Logger.Error($"Authorization endpoint id token 'sub' ({notification.JwtSecurityToken.Subject}) and 'iss' ({notification.JwtSecurityToken.Issuer}) claim values don't match with token endpoint 'sub' ({parsedIdToken.Subject}) and 'iss' ({parsedIdToken.Issuer}) claim values.");

                                    notification.HandleResponse();

                                    // TODO : redirect to friendly error page
                                    // does 302 redirect, but SEO is not your concern here
                                    // notification.Response.Redirect("/your/nice/error/page/address/here/");

                                    notification.Response.Write("Token endpoint identity token doesn't match autohorization endpoint returned identity token.");
                                    return;
                                }
                            }
                            catch (Exception ex)
                            {
                                Logger.Error($"Failed to validate token endpoint identity token against autohorization endpoint returned identity token.", ex);

                                notification.HandleResponse();

                                // TODO : redirect to friendly error page
                                // does 302 redirect, but SEO is not your concern here
                                // notification.Response.Redirect("/your/nice/error/page/address/here/");

                                notification.Response.Write("Failed to validate token endpoint identity token against autohorization endpoint returned identity token.");
                                return;
                            }
                        }
                        else
                        {
                            Logger.Information($"Token endpoint didn't return identity token for sub: {notification.JwtSecurityToken.Subject}.");
                        }

                        // get userinfo using the access token
                        var userInfoClient = new UserInfoClient(configuration.UserInfoEndpoint);
                        var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);

                        // check if there was an error fetching the user information
                        if (userInfoResponse.IsError)
                        {
                            Logger.Error($"There was an error retrieving the user information for sub: {notification.JwtSecurityToken.Subject}. Error: {userInfoResponse.Error}.");

                            notification.HandleResponse();

                            // TODO : redirect to friendly error page
                            // does 302 redirect, but SEO is not your concern here
                            // notification.Response.Redirect("/your/nice/error/page/address/here/");

                            notification.Response.Write($"Error retrieving user information. {userInfoResponse.Error}.");
                            return;
                        }

                        if (Logger.IsDebugEnabled())
                        {
                            Logger.Debug($"Userinfo received for sub: {notification.JwtSecurityToken.Subject}. Received claims: {GetClaimsAsString(userInfoResponse.Claims)}.");
                        }

                        // Create a new claims identity as the automatically created claimsidentity can contain claims that we don't need
                        // and we can keep the authentication cookie size smaller this way
                        // NOTE: Episerver uses the ClaimsIdentity name claim as the username (this will be also the display name when logged in), so make sure it is unique!
                        // Other claims synched automatically are (defined in class EPiServer.Security.ClaimTypeOptions, EPiServer.Framework):
                        // Email claim: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
                        // GivenName claim: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname
                        // Surname claim: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname

                        // create new claimsidentity and set name claim name to JwtClaimTypes.PreferredUserName and role claim to JwtClaimTypes.Role
                        // NOTE!: The RP MUST NOT rely upon this value being unique, as discussed in http://openid.net/specs/openid-connect-basic-1_0-32.html#ClaimStability
                        // as Episerver uses the Name claim as the username (unique) and also as the display name in edit view, we could use the sub claim but this could be a guid
                        // so for the sake of the demo I will use the JwtClaimTypes.PreferredUserName even though it is said that it can't be tusted to be unique and can contani special characters
                        // in real world cases you just need to know what claims are unique and displayable for the end user, email might be one option but then you need to check that you get it always
                        // in this demo I will always return the same username in the JwtClaimTypes.PreferredUserName as was used to login to the IdP
                        var authClaimsIdentity = new ClaimsIdentity(notification.AuthenticationTicket.Identity.AuthenticationType, CustomClaimNames.EpiUsername, JwtClaimTypes.Role);

                        // split claims to two sets: role claims and other claims
                        List<Claim> roleClaims = new List<Claim>();
                        List<Claim> otherClaims = new List<Claim>();

                        foreach (var c in userInfoResponse.Claims)
                        {
                            if (string.Compare(c.Type, CustomClaimNames.Permission, StringComparison.OrdinalIgnoreCase) == 0)
                            {
                                roleClaims.Add(c);
                            }
                            else
                            {
                                otherClaims.Add(c);
                            }
                        }

                        // get the preferred username claim and if it doesn't exist use sub claim value
                        string username = otherClaims.GetClaimValue(JwtClaimTypes.PreferredUserName) ?? notification.JwtSecurityToken.Subject;
                        authClaimsIdentity.AddClaim(new Claim(CustomClaimNames.EpiUsername, username));

                        // should we add the claim to allow publishing of content
                        bool addPublisherClaim = false;

                        // is the user admin
                        var adminUserClaim = roleClaims.Find(c => string.Compare(c.Value, PermissionGroupNames.WebSiteSuperUser, StringComparison.OrdinalIgnoreCase) == 0);

                        if (adminUserClaim != null)
                        {
                            authClaimsIdentity.AddClaim(new Claim(JwtClaimTypes.Role, EpiRoles.Admin));
                            addPublisherClaim = true;
                        }

                        // you could have a claim for users from previous CMS and then you could have a custom mapping from that claim to new claim(s) used by Episerver
                        //var oldEditorClaim = roleClaims.Find(c => string.Compare(c.Value, "BOGUS_OLD_CMS_USER", StringComparison.OrdinalIgnoreCase) == 0);
                        //if (oldEditorClaim != null)
                        //{
                        //    authClaimsIdentity.AddClaim(new Claim(JwtClaimTypes.Role, "WebEditors"));
                        //    addPublisherClaim = true;
                        //}

                        // is the user editor
                        var editUserClaim = roleClaims.Find(c => string.Compare(c.Value, PermissionGroupNames.WebSiteEditor, StringComparison.OrdinalIgnoreCase) == 0);

                        if (editUserClaim != null)
                        {
                            authClaimsIdentity.AddClaim(new Claim(JwtClaimTypes.Role, EpiRoles.Editor));
                            addPublisherClaim = true;
                        }

                        // is the user a reader without edit/publishing rights
                        var readerUserClaim = roleClaims.Find(c => string.Compare(c.Value, PermissionGroupNames.WebSiteReader, StringComparison.OrdinalIgnoreCase) == 0);

                        if (readerUserClaim != null)
                        {
                            authClaimsIdentity.AddClaim(new Claim(JwtClaimTypes.Role, EpiRoles.Editor));
                            // user will get the WebEditors role but not the role to publish/edit
                            // WebEditors role should only be used to grant access to the edit mode BUT not give any rights for content
                            // that is why we have the "SitePublishers" in this demo, we'll grant full permissions for content for this group
                            // but in real life scenario, you would have different and maybe more granular roles for different actions
                        }

                        // should we grant the publishing rights to the user
                        if (addPublisherClaim)
                        {
                            authClaimsIdentity.AddClaim(new Claim(JwtClaimTypes.Role, EpiRoles.Publisher));
                        }

                        // next get the email, givenname and surname claim values, our IdP uses JwtClaimTypes
                        // so this is not something that you can copy to your solution, but you need to check what claims your IdP returns
                        authClaimsIdentity.AddClaimFromSource(ClaimTypes.Email, otherClaims, JwtClaimTypes.Email);
                        authClaimsIdentity.AddClaimFromSource(ClaimTypes.GivenName, otherClaims, JwtClaimTypes.GivenName);
                        authClaimsIdentity.AddClaimFromSource(ClaimTypes.Surname, otherClaims, JwtClaimTypes.FamilyName);

                        // For now we don't need the access token, besides it expires in 60 minutes and we can't refresh it as we don't request for a refreshtoken
                        //authClaimsIdentity.AddClaim(new Claim(OpenIdConnectParameterNames.AccessToken, tokenResponse.AccessToken));
                        //authClaimsIdentity.AddClaim(new Claim("expires_at", DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn).ToString()));

                        // this is needed for the logout, logout uses id_token_hint
                        authClaimsIdentity.AddClaim(new Claim(OpenIdConnectParameterNames.IdToken, notification.ProtocolMessage.IdToken));

                        // replace the automatically created authenticationticket with our ticket which contains our minimal set of claims
                        // remember to pass in the original ticket properties for the new ticket
                        notification.AuthenticationTicket = new AuthenticationTicket(authClaimsIdentity, notification.AuthenticationTicket.Properties);

                        Logger.Information($"Authenticated and logging in user '{GetFullName(authClaimsIdentity.Claims)}' (sub: {notification.JwtSecurityToken.Subject}).");

                        // Sync user and the roles to EPiServer in the background
                        // See: https://world.episerver.com/documentation/developer-guides/CMS/security/integrate-azure-ad-using-openid-connect/
                        // Please note that until a user with a role has logged in, you can't apply permissions to that role (as Episerver doesn't naturally know about that role)
                        await ServiceLocator.Current.GetInstance<ISynchronizingUserService>().SynchronizeAsync(notification.AuthenticationTicket.Identity);
                    },
                    AuthenticationFailed = notification =>
                    {
                        Logger.Error($"Authentication failed: {notification.Exception.Message}");

                        notification.HandleResponse();

                        // TODO: redirect to a nice error page
                        // does 302 redirect, but SEO is not your concern here
                        // notification.Response.Redirect("/your/nice/error/page/address/here/");
                        notification.Response.Write(notification.Exception.Message);
                        return Task.FromResult(0);
                    },
                    SecurityTokenReceived = notification =>
                    {
                        // purely to log "stages" for demo and debugging, in real app usually you can leave this notification un-implemented

                        if (Logger.IsDebugEnabled())
                        {
                            try
                            {
                                Logger.Debug($"Security token received. Code: '{notification.ProtocolMessage.Code}', IdToken: '{notification.ProtocolMessage.IdToken}'.");
                            }
                            catch (Exception ex)
                            {
                                Logger.Error($"Security token received. Failed to read Code and IdToken for debug logging.", ex);
                            }
                        }

                        return Task.FromResult(0);
                    },
                    SecurityTokenValidated = notification =>
                    {
                        // purely to log "stages" for demo and debugging, in real app usually you can leave this notification un-implemented

                        if (Logger.IsDebugEnabled())
                        {
                            try
                            {
                                Logger.Debug($"Security token validated for sub: {notification.AuthenticationTicket.Identity.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject)?.Value}.");
                            }
                            catch (Exception ex)
                            {
                                Logger.Error($"Security token validated. Failed to read values from protocol message for debug logging.", ex);
                            }
                        }

                        return Task.FromResult(0);
                    },
                    MessageReceived = notification =>
                    {
                        // purely to log "stages" for demo and debugging, in real app usually you can leave this notification un-implemented

                        if (Logger.IsDebugEnabled())
                        {
                            Logger.Debug($"Message received.");
                        }

                        return Task.FromResult(0);
                    }
                }
            });

            // see: https://docs.microsoft.com/en-us/aspnet/aspnet/overview/owin-and-katana/owin-middleware-in-the-iis-integrated-pipeline#stage-markers
            app.UseStageMarker(PipelineStage.Authenticate);

            // TODO: your util url path here
            app.Map("/util/login.aspx", map =>
            {
                map.Run(ctx =>
                {
                    if (ctx.Authentication.User == null || !ctx.Authentication.User.Identity.IsAuthenticated)
                    {
                        // trigger authentication
                        ctx.Response.StatusCode = 401;
                    }
                    else
                    {
                        ctx.Response.Redirect("/");
                    }

                    return Task.FromResult(0);
                });
            });

            // TODO: your util url path here
            app.Map("/util/logout.aspx", map =>
            {
                map.Run(ctx =>
                {
                    ctx.Authentication.SignOut();
                    return Task.FromResult(0);
                });
            });

        }

        /// <summary>
        /// Simple check if the request is 'AJAX' request.
        /// </summary>
        /// <param name="request">IOwinRequest</param>
        /// <returns>true if the request is made with AJAX (or interpret so) otherwise false</returns>
        private static bool IsAjaxRequest(IOwinRequest request)
        {
            // look at reference: Brock Allen blog: https://brockallen.com/2013/10/27/using-cookie-authentication-middleware-with-web-api-and-401-response-codes/
            // if you want to support querystring to supply the X-Requested-With information
            // ASP.NET MVC implementation basically first checks querystring then form collectio then cookie then server variables and then fallback to HTTP header
            // i believe we can first check the HTTP header and then fallback to the other implementations or we could just check for th eheader
            // or copy same implementation as used in: System.Web.Mvc.dll, System.Web.Mvc.AjaxRequestExtensions

            if (request == null)
            {
                return false;
            }

            // taking copy to local member as the IOwinRequest.Headers implementation return always a new collection
            var headers = request.Headers;

            if (headers != null && string.Compare(headers["X-Requested-With"], "XMLHttpRequest", StringComparison.OrdinalIgnoreCase) == 0)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Enumerates all claims and creates a string of the claim type and value.
        /// </summary>
        /// <param name="claims">IEnumerable of claims</param>
        /// <returns>all claims as string</returns>
        private static string GetClaimsAsString(IEnumerable<Claim> claims)
        {
            if (claims == null || !claims.Any())
            {
                return string.Empty;
            }

            StringBuilder sb = new StringBuilder(512);

            foreach (var c in claims)
            {
                sb.Append($"[{c.Type}:{c.Value}], ");
            }

            if (sb.Length > 2)
            {
                // if we have something in the stringbuilder remove the last extra comma and whitespace from the end
                // by moving aka reducing the length of the underlying string
                sb.Length = sb.Length - 2;
            }

            return sb.ToString();
        }

        /// <summary>
        /// Get user full name from claims.
        /// </summary>
        /// <param name="claims">claims</param>
        /// <returns>empty string or users full name basedon claim values</returns>
        private static string GetFullName(IEnumerable<Claim> claims)
        {
            if (claims == null || !claims.Any())
            {
                return string.Empty;
            }

            var firstname = claims.FirstOrDefault(c => string.Compare(c.Type, JwtClaimTypes.GivenName, StringComparison.OrdinalIgnoreCase) == 0);
            var lastname = claims.FirstOrDefault(c => string.Compare(c.Type, JwtClaimTypes.FamilyName, StringComparison.OrdinalIgnoreCase) == 0);

            return $"{firstname?.Value} {lastname?.Value}";
        }
    }

    /// <summary>
    /// Contains configuration values for OpenId Connect.
    /// </summary>
    /// <remarks>
    /// <para>
    /// In real app you get these values from your configuration source.
    /// </para>
    /// </remarks>
    internal static class OIDCInMemoryConfiguration
    {
        // NOTE! If using https, you will need to have the port 443 also in the authority url, even though it is the default

        /// <summary>
        /// OIDC client id.
        /// </summary>
        public const string ClientId = "epi-alloy-mvc"; // TODO: change your client ID here
        /// <summary>
        /// OIDC client secret.
        /// </summary>
        public const string ClientSecret = "epi-alloy-mvc-very-secret"; // TODO: change your secret here
        /// <summary>
        /// OIDC authority. Also used to get OIDC discovery automatically if the identity provider is using the default well-known endpoint (/.well-known/openid-configuration).
        /// </summary>
        public const string Authority = "http://localhost:5000/";
        /// <summary>
        /// OIDC url where Identity provider is allowed to return tokens or authorization code.
        /// </summary>
        public const string WebAppOidcEndpoint = "http://localhost:48660"; // TODO: change your web app address/port here
        /// <summary>
        /// Where the client is redirected to after identity provider logout.
        /// </summary>
        public const string PostLogoutRedirectUrl = "http://localhost:48660"; // NOTE: http://localhost:48660 and http://localhost:48660/ are different addresses (the backslash at the end)!
        /// <summary>
        /// Is HTTPS required for the metadata endpoint.
        /// </summary>
        public const bool RequireHttpsMetadata = false;
        /// <summary>
        /// How long the web application authentication cookie is valid (in minutes in our example).
        /// </summary>
        public const int AuthCookieValidMinutes = 60;
    }
}
