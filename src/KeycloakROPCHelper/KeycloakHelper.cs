using KeycloakIdentityModel;
using KeycloakIdentityModel.Models.Responses;
using KeycloakIdentityModel.Utilities;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace KeycloakROPCHelper
{
    public static class KeycloakHelper
    {
        public static KeycloakAuthenticationOptions Options { get; private set; }
        public static void SetOptions(KeycloakAuthenticationOptions options)
        {
            Options = options;
            ValidateOptions();
        }
        public static ClaimsIdentity GetKeycloakIdentity(string username, string password)
        {
            return GetKeycloakIdentityAsync(username, password).Result;
        }
        public static async Task<ClaimsIdentity> GetKeycloakIdentityAsync(string username, string password)
        {
            if (Options == null)
            {
                throw new ArgumentNullException("options");
            }
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                throw new InvalidCredentialException("username or password is empty.");
            }
            var uriManager = await OidcDataManager.GetCachedContextAsync(Options);
            var response = SendHttpPostRequest(uriManager.GetTokenEndpoint(), uriManager.BuildROPCAccessTokenEndpointContent(username, password));

            var result = await response.Content.ReadAsStringAsync();
            var tokenrespones = new TokenResponse(result);

            var claimidentity = await KeycloakIdentity.ConvertFromTokenResponseAsync(Options, tokenrespones);
            var identity = await claimidentity.ToClaimsIdentityAsync();
            return new ClaimsIdentity(identity.Claims, Options.SignInAsAuthenticationSchema, identity.NameClaimType, identity.RoleClaimType);
        }

        private static HttpResponseMessage SendHttpPostRequest(Uri uri, HttpContent content = null)
        {
            HttpResponseMessage response;
            try
            {
                var client = new HttpClient();
                response = client.PostAsync(uri, content).Result;
            }
            catch (Exception exception)
            {
                throw new Exception("HTTP client URI is inaccessible", exception);
            }

            // Check for HTTP errors
            if (response.StatusCode == HttpStatusCode.BadRequest)
                throw new AuthenticationException(); // Assume bad credentials
            if (!response.IsSuccessStatusCode)
                throw new Exception("HTTP client returned an unrecoverable error");

            return response;
        }
        private static void ValidateOptions()
        {
            // Load web root path from config
            if (string.IsNullOrWhiteSpace(Options.VirtualDirectory))
                Options.VirtualDirectory = "/";
            Options.VirtualDirectory = NormalizeUrl(Options.VirtualDirectory);
            // Set default options
            if (string.IsNullOrWhiteSpace(Options.ResponseType))
                Options.ResponseType = "code";
            if (string.IsNullOrWhiteSpace(Options.Scope))
                Options.Scope = "openid";
            if (string.IsNullOrWhiteSpace(Options.CallbackPath))
                Options.CallbackPath = $"{Options.VirtualDirectory}/owin/security/keycloak/{Uri.EscapeDataString(Options.AuthenticationScheme)}/callback";
            if (string.IsNullOrWhiteSpace(Options.PostLogoutRedirectUrl))
                Options.PostLogoutRedirectUrl = Options.VirtualDirectory;

            if (Options.SignInAsAuthenticationSchema == null)
            {
                try
                {
                    //Options.SignInAsAuthenticationType = App.GetDefaultSignInAsAuthenticationType();
                    Options.SignInAsAuthenticationSchema = "";
                }
                catch (Exception)
                {
                    Options.SignInAsAuthenticationSchema = "";
                }
            }

            // Switch composite options

            if (Options.EnableWebApiMode)
            {
                Options.EnableBearerTokenAuth = true;
                Options.ForceBearerTokenAuth = true;
            }

            // Validate other options

            if (Options.ForceBearerTokenAuth && !Options.EnableBearerTokenAuth)
                Options.EnableBearerTokenAuth = true;

            Options.KeycloakUrl = NormalizeUrl(Options.KeycloakUrl);
            Options.CallbackPath = NormalizeUrlPath(Options.CallbackPath);

            // Final parameter validation
            KeycloakIdentity.ValidateParameters(Options);
        }
        private static string NormalizeUrl(string url)
        {
            if (url.EndsWith("/"))
            {
                url = url.TrimEnd('/');
            }
            return url;
        }

        private static string NormalizeUrlPath(string url)
        {
            if (!url.StartsWith("/"))
            {
                url = "/" + url;
            }
            return NormalizeUrl(url);
        }

    }
}
