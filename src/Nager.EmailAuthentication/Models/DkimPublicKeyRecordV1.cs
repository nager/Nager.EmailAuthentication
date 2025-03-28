namespace Nager.EmailAuthentication.Models
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
        /// A set of flags that define boolean attributes <strong>(t=)</strong>
        /// </summary>
        public string? Flags { get; set; }

        /// <summary>
        /// A colon-separated list of service types to which this record applies <strong>(s=)</strong>
        /// </summary>
        public string ServiceType { get; set; } = "*";

        /// <summary>
        /// Acceptable hash algorithms <strong>(h=)</strong>
        /// </summary>
        public string? AcceptableHashAlgorithms { get; set; }
    }
}
