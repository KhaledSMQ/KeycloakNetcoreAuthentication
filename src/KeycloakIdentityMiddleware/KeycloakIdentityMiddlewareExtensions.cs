using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace KeycloakIdentityMiddleware
{
    public static class KeycloakIdentityMiddlewareExtensions
    {
        public static IApplicationBuilder UseKeycloakIdentity(this IApplicationBuilder builder, KeycloakAuthenticationOptions options)
        {
            return builder.UseMiddleware<KeycloakIdentityMiddleware>(Options.Create(options));
        }
    }
}
