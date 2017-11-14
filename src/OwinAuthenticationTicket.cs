using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace AspNetTicketBridge
{
    public class OwinAuthenticationTicket
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OwinAuthenticationTicket"/> class
        /// </summary>
        /// <param name="identity"></param>
        /// <param name="properties"></param>
        public OwinAuthenticationTicket(ClaimsIdentity identity, AuthenticationProperties properties)
        {
            Identity = identity;
            Properties = properties ?? new AuthenticationProperties();
        }

        /// <summary>
        /// Gets the authenticated user identity.
        /// </summary>
        public ClaimsIdentity Identity { get; private set; }

        /// <summary>
        /// Additional state values for the authentication session.
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }
    }
}
