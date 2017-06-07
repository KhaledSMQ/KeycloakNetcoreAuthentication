using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using KeycloakIdentityMiddleware;

namespace KeycloakApp
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddMvc();
            services.AddAuthorization();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            loggerFactory.AddConsole(minLevel: LogLevel.Information);
            var logger = loggerFactory.CreateLogger("start");

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            const string persistentAuthScheme = "Mycookies";

            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                AuthenticationScheme = persistentAuthScheme,
                AutomaticAuthenticate = true,
            });

            app.UseKeycloakIdentity(new KeycloakAuthenticationOptions
            {
                ClientId = "KeycloakOwinAuthenticationSample", // *Required*
                ClientSecret = "9adf6cd2-3cb4-4c27-925e-780fca464443", // If using public authentication, delete this line
                AutomaticChallenge = true,
                Realm = "mdserver", // Don't change this unless told to do so
                KeycloakUrl = "http://192.168.0.46:8080/auth", // Enter your Keycloak URL here
                AuthenticationScheme = "KeycloakCoreAuthenticationSample_keycloak_auth",
                SignInAsAuthenticationSchema = persistentAuthScheme // Sets the above cookie with the Keycloak data
            });

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}