using KeycloakIdentityModel;
using KeycloakIdentityModel.Models.Responses;
using KeycloakIdentityModel.Utilities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace KeycloakIdentityMiddleware
{
    public class KeycloakAuthenticationHandler : AuthenticationHandler<KeycloakAuthenticationOptions>
    {
        private IMemoryCache _cache;
        private const string _cachePrefix = "oidc_state_";
        protected readonly TimeSpan _defaultCacheLife = new TimeSpan(0, 30, 0);

        public KeycloakAuthenticationHandler(IMemoryCache memoryCache) : base()
        {
            _cache = memoryCache;
        }

        public override async Task<bool> HandleRequestAsync()
        {
            // Check SignInAs identity for authentication update
            if (Context.User.Identity.IsAuthenticated)
            {
                await ValidateSignInAsIdentities();
            }
            var currUri = new Uri(CurrentUri);
            // Check for valid callback URI
            var callbackUri = await KeycloakIdentity.GenerateLoginCallbackUriAsync(Options, currUri);
            if (!Options.ForceBearerTokenAuth && currUri.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped) == callbackUri.ToString())
            {
                // Create authorization result from query
                var authResult = new AuthorizationResponse(currUri.Query);
                try
                {
                    // Validate passed state
                    var stateData = ReturnState(authResult.State);
                    if (stateData == null)
                    {
                        throw new Exception("Invalid state: Please reattempt the request");
                    }

                    // Parse properties from state data
                    AuthenticationProperties properties;
                    if (stateData.TryGetValue(Constants.CacheTypes.AuthenticationProperties, out object authpprop))
                    {
                        properties = authpprop as AuthenticationProperties ?? new AuthenticationProperties();
                    }
                    else
                    {
                        properties = new AuthenticationProperties();
                    }

                    // Process response
                    var kcIdentity = await KeycloakIdentity.ConvertFromAuthResponseAsync(Options, authResult, currUri);
                    var identity = await kcIdentity.ToClaimsIdentityAsync();
                    Context.User.AddIdentity(identity);

                    SignInAsAuthentication(identity, properties, Options.SignInAsAuthenticationSchema);

                    // Redirect back to the original secured resource, if any
                    if (!string.IsNullOrWhiteSpace(properties.RedirectUri) && Uri.IsWellFormedUriString(properties.RedirectUri, UriKind.Absolute))
                    {
                        Response.Redirect(properties.RedirectUri);
                        return true;
                    }
                }
                catch (Exception exception)
                {
                    await GenerateErrorResponseAsync(HttpStatusCode.BadRequest, "Bad Request", exception.Message);
                    return true;
                }
            }
            return false;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (Context.User.Identity.IsAuthenticated)
            {
                return await Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(Context.User, new AuthenticationProperties(), Options.AuthenticationScheme)));
            }
            return await Task.FromResult(AuthenticateResult.Skip());
        }
        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            if (!Context.User.Identity.IsAuthenticated)
            {
                await LoginRedirectAsync(new AuthenticationProperties
                {
                    IsPersistent = true,
                    AllowRefresh = true
                });
            }
            return true;
        }

        #region Private Helper Functions

        private void SignInAsAuthentication(ClaimsIdentity identity, AuthenticationProperties authProperties = null, string signInAuthType = null)
        {
            if (signInAuthType == Options.AuthenticationScheme) return;

            var signInIdentity = signInAuthType != null
                ? new ClaimsIdentity(identity.Claims, signInAuthType, identity.NameClaimType, identity.RoleClaimType)
                : identity;

            if (string.IsNullOrWhiteSpace(signInIdentity.AuthenticationType)) return;

            if (authProperties == null)
            {
                authProperties = new AuthenticationProperties
                {
                    // TODO: Make these configurable
                    AllowRefresh = true,
                    IsPersistent = true,
                    ExpiresUtc = DateTime.UtcNow.Add(Options.SignInAsAuthenticationExpiration)
                };
            }

            // Parse expiration date-time
            var expirations = new List<string>
            {
                identity.Claims.FirstOrDefault(c => c.Type == Constants.ClaimTypes.RefreshTokenExpiration)?.Value,
                identity.Claims.FirstOrDefault(c => c.Type == Constants.ClaimTypes.AccessTokenExpiration)?.Value
            };

            foreach (var expStr in expirations)
            {
                DateTime expDate;
                if (expStr == null || !DateTime.TryParse(expStr, CultureInfo.InvariantCulture, DateTimeStyles.None, out expDate))
                    continue;
                authProperties.ExpiresUtc = expDate.Add(Options.TokenClockSkew);
                break;
            }
            Context.Authentication.SignInAsync(signInAuthType, new ClaimsPrincipal(signInIdentity), authProperties);
        }

        private async Task ValidateSignInAsIdentities()
        {
            foreach (var origIdentity in Context.User.Identities)
            {
                try
                {
                    if (!origIdentity.HasClaim(Constants.ClaimTypes.AuthenticationType, Options.AuthenticationScheme))
                        continue;
                    var kcIdentity = await KeycloakIdentity.ConvertFromClaimsIdentityAsync(Options, origIdentity);
                    if (!kcIdentity.IsTouched) continue;

                    // Replace identity if expired
                    var identity = await kcIdentity.ToClaimsIdentityAsync();
                    Context.User = new ClaimsPrincipal(identity);
                    SignInAsAuthentication(identity, null, Options.SignInAsAuthenticationSchema);
                }
                catch (AuthenticationException)
                {
                    await Context.Authentication.SignOutAsync(origIdentity.AuthenticationType);
                }
                // ReSharper disable once RedundantCatchClause
                catch (Exception)
                {
                    // TODO: Some kind of exception logging, maybe log the user out
                    throw;
                }
            }
        }

        private async Task GenerateUnauthorizedResponseAsync(string errorMessage)
        {
            await GenerateErrorResponseAsync(Response, HttpStatusCode.Unauthorized, "Unauthorized", errorMessage);
        }

        private async Task GenerateErrorResponseAsync(HttpStatusCode statusCode, string reasonPhrase, string errorMessage)
        {
            await GenerateErrorResponseAsync(Response, statusCode, reasonPhrase, errorMessage);
        }

        private static async Task GenerateErrorResponseAsync(HttpResponse response, HttpStatusCode statusCode,
            string reasonPhrase, string errorMessage)
        {
            // Generate error response
            var task = response.WriteAsync(errorMessage);
            response.StatusCode = (int)statusCode;
            response.ContentType = "text/plain";
            await task;
        }

        #endregion

        private string CreateState(Dictionary<string, object> stateData, TimeSpan? lifeTime = null)
        {
            if (lifeTime == null) lifeTime = _defaultCacheLife;

            // Generate state key
            var stateKey = $"{_cachePrefix}{Guid.NewGuid().ToString("N")}";

            // Insert into cache
            _cache.Set(stateKey, stateData, lifeTime.Value);

            return stateKey;
        }

        private Dictionary<string, object> ReturnState(string stateKey)
        {
            if (_cache.TryGetValue(stateKey, out object val))
            {
                _cache.Remove(stateKey);
                return val as Dictionary<string, object>;
            }
            return null;
        }

        #region OIDC Helper Functions
        private async Task LoginRedirectAsync(AuthenticationProperties properties)
        {
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            // Create state
            var stateData = new Dictionary<string, object>
            {
                {Constants.CacheTypes.AuthenticationProperties, properties}
            };
            var state = CreateState(stateData);

            // Redirect response to login
            Response.Redirect((await KeycloakIdentity.GenerateLoginUriAsync(Options, new Uri(CurrentUri), state)).ToString());
        }

        private async Task LogoutRedirectAsync()
        {
            // Redirect response to logout
            Response.Redirect((await KeycloakIdentity.GenerateLogoutUriAsync(Options, new Uri(CurrentUri))).ToString());
        }

        #endregion
    }
}