namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Dkim Public Key Record Data Fragment
    /// </summary>
    public class DkimPublicKeyRecordDataFragment
    {
        /// <summary>
        /// Dkim Version <strong>(v=)</strong>
        /// </summary>
        public string? Version { get; set; }

        /// <summary>
        /// Key Type <strong>(k=)</strong>
        /// </summary>
        public string? KeyType { get; set; }

        /// <summary>
        /// Notes that may be of interest to a human <strong>(n=)</strong>
        /// </summary>
        public string? Notes { get; set; }

        /// <summary>
        /// Public key data <strong>(p=)</strong>
        /// </summary>
        public string? PublicKeyData { get; set; }

        /// <summary>
        /// Granularity of the key
        /// </summary>
        public string? Granularity { get; set; }

        /// <summary>
        /// A set of flags that define boolean attributes <strong>(t=)</strong>
        /// </summary>
        public string? Flags { get; set; }
    }
}
