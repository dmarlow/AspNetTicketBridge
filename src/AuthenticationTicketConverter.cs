using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Security.Principal;

namespace AspNetTicketBridge
{
    /// <summary>
    /// Conversion between AuthenticationTicket (v5)
    /// and OwinAuthenticationTicket (v3)
    /// </summary>
    public static class AuthenticationTicketConverter
    {
        /// <summary>
        /// Converts a v3 ticket to a v5.
        /// </summary>
        public static AuthenticationTicket Convert(OwinAuthenticationTicket ticket, string authScheme)
        {
            var newTicket = new AuthenticationTicket(new ClaimsPrincipal(ticket.Identity),
                        ticket.Properties, authScheme);
            return newTicket;
        }
        /// <summary>
        /// Converts a v5 ticket to  v3 ticket
        /// </summary>
        /// <param name="ticket"></param>
        /// <returns></returns>
        public static OwinAuthenticationTicket Convert(AuthenticationTicket ticket)
        {
            var newTicket = new OwinAuthenticationTicket(
                GenerateClaimsIdentity(ticket.Principal), ticket.Properties);
            return newTicket;
        }

        private static ClaimsIdentity GenerateClaimsIdentity(ClaimsPrincipal principal)
        {
            if (principal.Identity is ClaimsIdentity ci)
                return ci;

            return new ClaimsIdentity(principal.Claims, principal.Identity.AuthenticationType);
        }
    }
}
