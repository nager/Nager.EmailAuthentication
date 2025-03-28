namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Dkim Public Key Record Data Fragment
    /// </summary>
    public class DkimPublicKeyRecordDataFragmentV1 : DkimPublicKeyRecordDataFragmentBase
    {
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
        /// Granularity of the key <strong>(g=)</strong>, introduced in RFC 4871 and removed in RFC 6376.
        /// </summary>
        /// <remarks>set to obsolete</remarks>
        public string? Granularity { get; set; }

        /// <summary>
        /// A set of flags that define boolean attributes <strong>(t=)</strong>
        /// </summary>
        public string? Flags { get; set; }

        /// <summary>
        /// A colon-separated list of service types to which this record applies <strong>(s=)</strong>
        /// </summary>
        public string? ServiceType { get; set; }

        /// <summary>
        /// Acceptable hash algorithms <strong>(h=)</strong>
        /// </summary>
        public string? AcceptableHashAlgorithms { get; set; }
    }
}
