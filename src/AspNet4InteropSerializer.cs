using Microsoft.AspNetCore.Authentication;

namespace AspNetTicketBridge
{
    internal class AspNet4InteropSerializer : IDataSerializer<AuthenticationTicket>
    {
        public static readonly AspNet4InteropSerializer Default = new AspNet4InteropSerializer();
        private static readonly OwinTicketSerializer _serializer = new OwinTicketSerializer();

        public byte[] Serialize(AuthenticationTicket model)
        {
            var v3Ticket = AuthenticationTicketConverter.Convert(model);
            return _serializer.Serialize(v3Ticket);
        }

        public AuthenticationTicket Deserialize(byte[] data)
        {
            var v3Ticket = _serializer.Deserialize(data);
            return AuthenticationTicketConverter.Convert(v3Ticket, "ASPNET Interop");
        }
    }
}