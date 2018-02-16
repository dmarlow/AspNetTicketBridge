# AspNetTicketBridge

Decrypts MachineKey protected AuthenticationTicket objects created by ASP.NET to be used in ASP.NET Core.

This MachineKey decryptor uses HMACSHA1 and AES with the decryptionKey and validationKey from your web.config to decrypt OAuth tokens generated from OWIN.

`<machineKey compatibilityMode="Framework45" decryption="AES" decryptionKey="....." validation="SHA1" validationKey="....." />`

## Example

```
string validationKey = "<value from old web.config/machineKey/validationKey>";
string decryptionKey = "<value from old web.config/machineKey/decryptionKey>";

// Decrypt the token
var ticket = MachineKeyTicketUnprotector.UnprotectOAuthToken(token, decryptionKey, validationKey);

// The ticket is in v3 format and needs to be converted to v5 (ASP.NET Core 2.0).
// Can use whatever you want for AuthScheme
var newTicket = AuthenticationTicketConverter.Convert(ticket, AuthScheme);

// If using a custom AuthenticationHandler, you can return the new ticket 
// in the HandleAuthenticateAsync method.
var result = AuthenticateResult.Success(newTicket);
```

Special thanks for [Umar Karimabadi](https://stackoverflow.com/users/7310452/umar-karimabadi) for doing all of the heavy lifting. For more information, see here: https://stackoverflow.com/questions/46546254/using-machine-keys-for-idataprotector-asp-net-core
