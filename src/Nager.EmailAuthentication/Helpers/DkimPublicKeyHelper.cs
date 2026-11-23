using System.Security.Cryptography;

namespace Nager.EmailAuthentication.Helpers
{
    /// <summary>
    /// Dkim Public Key Helper
    /// </summary>
    internal static class DkimPublicKeyHelper
    {
        private const int Ed25519KeyLength = 32;

        /// <summary>
        /// Determines the length of the public key of a DKIM public key record in bits.
        /// </summary>
        /// <param name="keyType">The key type of the record (k=), "rsa" or "ed25519".</param>
        /// <param name="publicKeyData">The base64 encoded public key of the record (p=).</param>
        /// <param name="keyLength">The length of the key in bits, if successful.</param>
        /// <returns><see langword="true"/> if the public key data is a key of the given type; otherwise <see langword="false"/>.</returns>
        public static bool TryGetKeyLength(
            string keyType,
            string publicKeyData,
            out int keyLength)
        {
            keyLength = 0;

            // The key can be split into several strings, whitespace is not part of the data (RFC 6376 section 3.6.1)
            var base64 = string.Concat(publicKeyData.Where(o => !char.IsWhiteSpace(o)));
            if (base64.Length == 0)
            {
                return false;
            }

            var publicKey = new byte[base64.Length];
            if (!Convert.TryFromBase64String(base64, publicKey, out var bytesWritten))
            {
                return false;
            }

            publicKey = publicKey[..bytesWritten];

            if (keyType.Equals("ed25519", StringComparison.OrdinalIgnoreCase))
            {
                // The raw public key (RFC 8463 section 4.2)
                if (publicKey.Length != Ed25519KeyLength)
                {
                    return false;
                }

                keyLength = Ed25519KeyLength * 8;
                return true;
            }

            if (keyType.Equals("rsa", StringComparison.OrdinalIgnoreCase))
            {
                return TryGetRsaKeyLength(publicKey, out keyLength);
            }

            return false;
        }

        private static bool TryGetRsaKeyLength(
            byte[] publicKey,
            out int keyLength)
        {
            keyLength = 0;

            try
            {
                using var rsa = RSA.Create();

                try
                {
                    // SubjectPublicKeyInfo (RFC 6376 section 3.6.1)
                    rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                }
                catch (CryptographicException)
                {
                    // Some records contain the RSAPublicKey without the algorithm identifier (RFC 8301 section 3.2)
                    rsa.ImportRSAPublicKey(publicKey, out _);
                }

                keyLength = rsa.KeySize;
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
            catch (PlatformNotSupportedException)
            {
                return false;
            }
        }
    }
}
