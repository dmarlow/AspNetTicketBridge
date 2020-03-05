using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace AspNetTicketBridge
{
    /// <summary>
    /// Class that handles reading and writing to a AspNet 4.X compatible authentication
    /// ticket data format.
    /// </summary>
    public class AspNet4TicketDataFormat : SecureDataFormat<AuthenticationTicket>
    {
        /// <summary>
        /// Create a new AspNet4TicketDataFormat with a IDataProtector
        /// See MachineKeyDataProtector
        /// </summary>
        /// <param name="protector"></param>
        public AspNet4TicketDataFormat(IDataProtector protector)
            : base(AspNet4InteropSerializer.Default, protector)
        {
        }
    }
}