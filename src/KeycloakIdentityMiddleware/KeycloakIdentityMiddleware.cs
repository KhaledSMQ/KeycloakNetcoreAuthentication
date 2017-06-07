using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.DataProtection;
using System.Text.Encodings.Web;
using KeycloakIdentityModel.Utilities;
using System.Collections.Concurrent;
using KeycloakIdentityModel;
using Microsoft.Extensions.Caching.Memory;
using System.Runtime.CompilerServices;

namespace KeycloakIdentityMiddleware
{
    public class KeycloakIdentityMiddleware : AuthenticationMiddleware<KeycloakAuthenticationOptions>
    {
        private ConcurrentDictionary<string, KeycloakAuthenticationOptions> KeycloakOptionStore = new ConcurrentDictionary<string, KeycloakAuthenticationOptions>();
        private IMemoryCache _cache;
        public KeycloakIdentityMiddleware(RequestDelegate next,
            IOptions<KeycloakAuthenticationOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            IMemoryCache memoryCache)
            : base(next, options, loggerFactory, encoder)
        {
            _cache = memoryCache;
            ValidateOptions();
        }

        protected override AuthenticationHandler<KeycloakAuthenticationOptions> CreateHandler()
        {
            return new KeycloakAuthenticationHandler(_cache);
        }

        private void ValidateOptions()
        {
            // Check to ensure authentication type isn't already used
            var authType = Options.AuthenticationScheme;
            if (!KeycloakOptionStore.TryAdd(authType, Options))
            {
                throw new Exception($"KeycloakAuthenticationOptions: Authentication type '{authType}' already used; required unique");
            }

            // Verify required options
            if (Options.KeycloakUrl == null)
                ThrowOptionNotFound(nameof(Options.KeycloakUrl));
            if (Options.Realm == null)
                ThrowOptionNotFound(nameof(Options.Realm));

            // Load web root path from config
            if (string.IsNullOrWhiteSpace(Options.VirtualDirectory))
                Options.VirtualDirectory = "/";
            Options.VirtualDirectory = NormalizeUrl(Options.VirtualDirectory);
            if (!Uri.IsWellFormedUriString(Options.VirtualDirectory, UriKind.Relative))
                ThrowInvalidOption(nameof(Options.VirtualDirectory));

            // Set default options
            if (string.IsNullOrWhiteSpace(Options.ResponseType))
                Options.ResponseType = "code";
            if (string.IsNullOrWhiteSpace(Options.Scope))
                Options.Scope = "openid";
            if (string.IsNullOrWhiteSpace(Options.CallbackPath))
                Options.CallbackPath =
                    $"{Options.VirtualDirectory}/owin/security/keycloak/{Uri.EscapeDataString(Options.AuthenticationScheme)}/callback";
            if (string.IsNullOrWhiteSpace(Options.PostLogoutRedirectUrl))
                Options.PostLogoutRedirectUrl = Options.VirtualDirectory;

            if (Options.SignInAsAuthenticationSchema == null)
            {
                Options.SignInAsAuthenticationSchema = "";
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

        private void ThrowOptionNotFound(string optionName)
        {
            var message = $"KeycloakAuthenticationOptions [id:{Options.AuthenticationScheme}] : Required option '{optionName}' not set";
            throw new Exception(message);
        }

        private void ThrowInvalidOption(string optionName, Exception inner = null)
        {
            var message = $"KeycloakAuthenticationOptions [id:{Options.AuthenticationScheme}] : Provided option '{optionName}' is invalid";
            throw inner == null ? new Exception(message) : new Exception(message, inner);
        }
    }
}
