using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Keycloak;

[assembly: OwinStartup(typeof(OwinApp.Startup))]
namespace OwinApp
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // Name of the persistent authentication middleware for lookup
            const string persistentAuthType = "KeycloakOwinAuthenticationSample_cookie_auth";

            // --- Cookie Authentication Middleware - Persists user sessions between requests
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = persistentAuthType
            });
            app.SetDefaultSignInAsAuthenticationType(persistentAuthType); // Cookie is primary session store

            // --- Keycloak Authentication Middleware - Connects to central Keycloak database
            app.UseKeycloakAuthentication(new KeycloakAuthenticationOptions
            {
                ClientId = "KeycloakOwinAuthenticationSample", // *Required*
                ClientSecret = "9adf6cd2-3cb4-4c27-925e-780fca464443", // If using public authentication, delete this line
                VirtualDirectory = "", // Set this if you use a virtual directory when deploying to IIS

                // Instance-Specific Settings
                Realm = "mdserver", // Don't change this unless told to do so
                KeycloakUrl = "http://192.168.0.46:8080/auth", // Enter your Keycloak URL here

                // Template-Specific Settings
                SignInAsAuthenticationType = persistentAuthType, // Sets the above cookie with the Keycloak data
                AuthenticationType = "KeycloakOwinAuthenticationSample_keycloak_auth", // Unique identifier for the auth middleware
            });
        }
    }
}