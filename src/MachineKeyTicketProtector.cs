using Microsoft.AspNetCore.WebUtilities;
using System.Security.Claims;

namespace AspNetTicketBridge
{
    public static class MachineKeyTicketProtector
    {
        /// <summary>
        /// Serializes, encrypts and encodes an AuthenticationTicket        
        /// created by OWIN's OAuth server implementation for the access token.
        /// </summary>
        /// <param name="ticket">The v3 AuthenticationTicket</param>
        /// <param name="decryptionKey">The machineKey decryptionKey found in your web.config</param>
        /// <param name="validationKey">The machineKey validationKey found in your web.config</param>
        /// <param name="decryptionAlgorithm">The machineKey decryptionAlgorithm found in your web.config (Auto == AES)</param>
        /// <param name="validationAlgorithm">The machineKey validationAlgorithm found in your web.config</param>
        /// <returns>An encoded string</returns>
        public static string ProtectOAuthToken(OwinAuthenticationTicket ticket, string decryptionKey, string validationKey,
            string decryptionAlgorithm = "AES", string validationAlgorithm = "HMACSHA1")
        {
            var serializer = new OwinTicketSerializer();
            var serializedData = serializer.Serialize(ticket);

            var protectedData = Protect(serializedData, decryptionKey, validationKey,
                decryptionAlgorithm, validationAlgorithm,
                "User.MachineKey.Protect",
                "Microsoft.Owin.Security.OAuth", "Access_Token", "v1");

            var encoded = WebEncoders.Base64UrlEncode(protectedData);
            return encoded;
        }

        /// <summary>
        /// Serializes, encrypts and encodes an AuthenticationTicket        
        /// created by OWIN's OAuth server implementation for the refresh token.
        /// </summary>
        /// <param name="ticket">The v3 AuthenticationTicket</param>
        /// <param name="decryptionKey">The machineKey decryptionKey found in your web.config</param>
        /// <param name="validationKey">The machineKey validationKey found in your web.config</param>
        /// <param name="decryptionAlgorithm">The machineKey decryptionAlgorithm found in your web.config (Auto == AES)</param>
        /// <param name="validationAlgorithm">The machineKey validationAlgorithm found in your web.config</param>
        /// <returns>An encoded string</returns>
        public static string ProtectOAuthRefreshToken(OwinAuthenticationTicket ticket, string decryptionKey, string validationKey,
            string decryptionAlgorithm = "AES", string validationAlgorithm = "HMACSHA1")
        {
            var serializer = new OwinTicketSerializer();
            var serializedData = serializer.Serialize(ticket);

            var protectedData = Protect(serializedData, decryptionKey, validationKey,
                decryptionAlgorithm, validationAlgorithm,
                "User.MachineKey.Protect",
                "Microsoft.Owin.Security.OAuth", "Refresh_Token", "v1");

            var encoded = WebEncoders.Base64UrlEncode(protectedData);
            return encoded;
        }

        /// <summary>
        /// Serializes, encrypts and encodes an AuthenticationTicket 
        /// created by OWIN's cookie authentication system.
        /// </summary>
        /// <param name="ticket">The v3 AuthenticationTicket</param>
        /// <param name="decryptionKey">The machineKey decryptionKey found in your web.config</param>
        /// <param name="validationKey">The machineKey validationKey found in your web.config</param>
        /// <param name="decryptionAlgorithm">The machineKey decryptionAlgorithm found in your web.config (Auto == AES)</param>
        /// <param name="validationAlgorithm">The machineKey validationAlgorithm found in your web.config</param>
        /// <returns>An encoded string</returns>
        public static string ProtectCookie(OwinAuthenticationTicket ticket, string decryptionKey, string validationKey,
            string decryptionAlgorithm = "AES", string validationAlgorithm = "HMACSHA1")
        {
            var serializer = new OwinTicketSerializer();
            var serializedData = serializer.Serialize(ticket);

            var protectedData = Protect(serializedData, decryptionKey, validationKey,
                decryptionAlgorithm, validationAlgorithm,
                "User.MachineKey.Protect",
                "Microsoft.Owin.Security.Cookies.CookieAuthenticationMiddleware", "ApplicationCookie", "v1");

            var encoded = WebEncoders.Base64UrlEncode(protectedData);
            return encoded;
        }

        public static byte[] Protect(byte[] serializedData, string decryptionKey, string validationKey,
            string decryptionAlgorithm, string validationAlgorithm,
            string primaryPurpose, params string[] purposes)
        {
            var protectedData = MachineKey.Protect(serializedData, validationKey, decryptionKey,
                decryptionAlgorithm, validationAlgorithm,
                primaryPurpose, purposes);

            return protectedData;
        }
    }
}
