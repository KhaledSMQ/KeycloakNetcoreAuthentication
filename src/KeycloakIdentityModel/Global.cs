using System.Reflection;

namespace KeycloakIdentityModel
{
    public static class Global
    {
        public static string GetVersion()
        {
            return Assembly.GetEntryAssembly().GetName().Version.ToString();
        }

        public static bool CheckVersion(string version)
        {
            return GetVersion() == version;
        }
    }
}