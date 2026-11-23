namespace Nager.EmailAuthentication.Models.Dkim
{
    /// <summary>
    /// Dkim Public Key Record
    /// </summary>
    public class DkimPublicKeyRecordV1 : DkimPublicKeyRecordBase
    {
        /// <summary>
        /// Key Type <strong>(k=)</strong>
        /// </summary>
        public string KeyType { get; set; } = "rsa";

        /// <summary>
        /// Notes that may be of interest to a human <strong>(n=)</strong>
        /// </summary>
        public string? Notes { get; set; }

        /// <summary>
        /// Public key data <strong>(p=)</strong>
        /// </summary>
        public required string PublicKeyData { get; set; }

        /// <summary>
        /// The public key has been revoked, the public key data is empty <strong>(p=)</strong>
        /// </summary>
        public bool IsRevoked => string.IsNullOrWhiteSpace(this.PublicKeyData);

        /// <summary>
        /// Length of the public key in bits (e.g., 2048 for an RSA key, 256 for an Ed25519 key).
        /// <see langword="null"/> if the key has been revoked or the public key data is not a key of the key type.
        /// </summary>
        public int? KeyLength { get; set; }

        /// <summary>
        /// A set of flags that define boolean attributes <strong>(t=)</strong>
        /// </summary>
        public string? Flags { get; set; }

        /// <summary>
        /// The domain is testing DKIM, flag "y" <strong>(t=)</strong>.
        /// Verifiers must not treat messages from signers in testing mode differently from unsigned email.
        /// </summary>
        public bool IsTestMode => this.HasFlag("y");

        /// <summary>
        /// The domain of the "i=" tag of a signature must be the same as the domain of the "d=" tag
        /// and not a subdomain of it, flag "s" <strong>(t=)</strong>
        /// </summary>
        public bool IsStrictIdentity => this.HasFlag("s");

        /// <summary>
        /// A colon-separated list of service types to which this record applies <strong>(s=)</strong>
        /// </summary>
        public string ServiceType { get; set; } = "*";

        /// <summary>
        /// Acceptable hash algorithms <strong>(h=)</strong>
        /// </summary>
        public string? AcceptableHashAlgorithms { get; set; }

        private bool HasFlag(string flag)
        {
            return this.Flags?
                .Split(':', StringSplitOptions.TrimEntries)
                .Contains(flag, StringComparer.OrdinalIgnoreCase) == true;
        }
    }
}
