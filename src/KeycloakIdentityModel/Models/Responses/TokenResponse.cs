using System.Collections.Specialized;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json.Linq;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;

namespace KeycloakIdentityModel.Models.Responses
{
    public class TokenResponse : OidcResponse
    {
        public TokenResponse(string encodedJson)
            : this(JObject.Parse(encodedJson))
        {
        }

        public TokenResponse(JObject json)
        {
            var authResult = new Dictionary<string, StringValues>();

            // Convert JSON to NameValueCollection type
            foreach (var item in json)
                authResult.Add(item.Key, item.Value.ToString());

            InitFromRequest(authResult);
        }

        public TokenResponse(string accessToken, string idToken, string refreshToken)
        {
            IdToken = idToken;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
        }

        public string ExpiresIn { get; private set; }
        public string TokenType { get; private set; }

        public string IdToken { get; private set; }
        public string AccessToken { get; private set; }
        public string RefreshToken { get; private set; }

        protected new void InitFromRequest(Dictionary<string, StringValues> authResult)
        {
            base.InitFromRequest(authResult);

            ExpiresIn = authResult[OpenIdConnectParameterNames.ExpiresIn];
            TokenType = authResult[OpenIdConnectParameterNames.TokenType];

            IdToken = authResult[OpenIdConnectParameterNames.IdToken];
            AccessToken = authResult[OpenIdConnectParameterNames.AccessToken];
            RefreshToken = authResult[Constants.OpenIdConnectParameterNames.RefreshToken];
        }
    }
}