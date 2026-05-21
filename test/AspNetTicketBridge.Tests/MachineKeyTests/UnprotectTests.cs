using NUnit.Framework;
using System;

namespace AspNetTicketBridge.Tests.MachineKeyTests
{
    /// <summary>
    /// These tests exercise the MachineKey.Unprotect method directly with known inputs and outputs to ensure that the decryption
    /// and validation logic is working as expected.
    /// </summary>
    public class UnprotectTests
    {
        private const string ValidationKey = "B28DF55FE73C68237A30C02A9F521C7297B1DC30F2B6C5CE6C8EBA1319DF0D895682BA56AB5DFD0A63F791D658B7938E9920D87110D206BF159F924EA5BD32C8";
        private const string DecryptionKey = "E16163E9394BA9B55F5DF1CA175AD607FD1773EF44ADFE59";
        private const string PrimaryPurpose = "User.MachineKey.Protect";

        [Test]
        [TestCase("ttDJtslU+IT5BEv5hgjnf3Hfi+kK9Ji/zj50NmoJxMxEF52UhPZNTC9gsgMmJwiXplehjQ==", "AES", "HMACSHA1")]
        [TestCase("9Osam2LN5bEqIHChlQbpU8ykoZn4ikFMhys9qFieqpaqWbix9uXnBB9oPJlOhKUcZT3Kf919vWtoj89lHL6RCg==", "AES", "HMACSHA256")]
        public void CanUnprotectEncryptedData(string protectedData, string decryptionAlgorithmName, string validationAlgorithmName)
        {
            var protectedBytes = Convert.FromBase64String(protectedData);

            var decryptedBytes = MachineKey.Unprotect(
                protectedBytes,
                ValidationKey,
                DecryptionKey,
                decryptionAlgorithmName,
                validationAlgorithmName,
                PrimaryPurpose);

            var decryptedString = System.Text.Encoding.UTF8.GetString(decryptedBytes);

            Assert.That(decryptedString, Is.EqualTo("Hello, World!"));
        }
    }
}
