using System;
using System.Collections.Specialized;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;

namespace KeycloakIdentityModel.Models.Responses
{
    public class AuthorizationResponse : OidcResponse
    {
        public AuthorizationResponse(string query)
        {
            InitFromRequest(QueryHelpers.ParseQuery(query));

            if (!Validate())
            {
                throw new ArgumentException("Invalid query string used to instantiate an AuthorizationResponse");
            }
        }

        public string Code { get; private set; }
        public string State { get; private set; }

        protected new void InitFromRequest(Dictionary<string, StringValues> authResult)
        {
            base.InitFromRequest(authResult);

            if (authResult.TryGetValue(OpenIdConnectParameterNames.Code, out StringValues code))
            {
                Code = code;
            }
            if (authResult.TryGetValue(OpenIdConnectParameterNames.State, out StringValues state))
            {
                State = state;
            }
        }

        public bool Validate()
        {
            return !string.IsNullOrWhiteSpace(Code) && !string.IsNullOrWhiteSpace(State);
        }
    }
}