using System;
using System.Collections.Specialized;
using Microsoft.IdentityModel.Protocols;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace KeycloakIdentityModel.Models.Responses
{
    public abstract class OidcResponse
    {
        public string Error { get; private set; }
        public string ErrorUri { get; private set; }
        public string ErrorDescription { get; private set; }

        protected void InitFromRequest(Dictionary<string, StringValues> authResult)
        {
            if (authResult.TryGetValue(OpenIdConnectParameterNames.Error, out StringValues error))
            {
                Error = error;
            }
            if (authResult.TryGetValue(OpenIdConnectParameterNames.ErrorUri, out StringValues erroruri))
            {
                ErrorUri = erroruri;
            }
            if (authResult.TryGetValue(OpenIdConnectParameterNames.ErrorDescription, out StringValues errordesc))
            {
                ErrorDescription = errordesc;
            }
        }

        public bool IsSuccessfulResponse()
        {
            return Error == null;
        }

        public void ThrowIfError()
        {
            if (!IsSuccessfulResponse())
            {
                throw new Exception(
                    $"OIDC Error in AuthorizationResult [{Error}]: {ErrorDescription ?? "NO DESCRIPTION"} (URI: '{ErrorUri ?? "N/A"}')");
            }
        }
    }
}