namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Dkim Public Key Record
    /// </summary>
    public class DkimPublicKeyRecord
    {
        /// <summary>
        /// Dkim Version <strong>(v=)</strong>
        /// </summary>
        public required string Version { get; set; } = "DKIM1";

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
        /// A set of flags that define boolean attributes <strong>(t=)</strong>
        /// </summary>
        public string? Flags { get; set; }
    }
}
