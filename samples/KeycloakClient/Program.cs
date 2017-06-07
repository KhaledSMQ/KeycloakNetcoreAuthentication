using KeycloakROPCHelper;
using System;

namespace KeycloakClient
{
    class Program
    {
        static void Main(string[] args)
        {
            var options = new KeycloakAuthenticationOptions
            {
                ClientId = "KeycloakOwinAuthenticationSample", // *Required*
                ClientSecret = "9adf6cd2-3cb4-4c27-925e-780fca464443", // If using public authentication, delete this line
                VirtualDirectory = "", // Set this if you use a virtual directory when deploying to IIS
                AutomaticChallenge = true,
                // Instance-Specific Settings
                Realm = "mdserver", // Don't change this unless told to do so
                KeycloakUrl = "http://192.168.0.46:8080/auth", // Enter your Keycloak URL here
                AuthenticationScheme = "KeycloakOwinAuthenticationSample_keycloak_auth",
                // Template-Specific Settings
                SignInAsAuthenticationSchema = "MyCookieMiddlewareInstance" // Sets the above cookie with the Keycloak data
            };
            KeycloakHelper.SetOptions(options);
            var identity = KeycloakHelper.GetKeycloakIdentity("user1", "user1");

            Console.ReadLine();
        }
    }
}