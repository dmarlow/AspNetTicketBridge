using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace AspNetTicketBridge
{
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
    }
}
