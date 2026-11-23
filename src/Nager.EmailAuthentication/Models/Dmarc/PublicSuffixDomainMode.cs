namespace Nager.EmailAuthentication.Models.Dmarc
{
    /// <summary>
    /// Defines whether a DMARC record is published for a Public Suffix Domain (PSD), the "psd" tag of RFC 9989.
    /// The value is used to determine the Organizational Domain during the DNS Tree Walk.
    /// </summary>
    public enum PublicSuffixDomainMode
    {
        /// <summary>
        /// The domain is not a Public Suffix Domain, it may or may not be an Organizational Domain ("u", the default).
        /// </summary>
        Unknown,

        /// <summary>
        /// The domain is a Public Suffix Domain ("y").
        /// </summary>
        Yes,

        /// <summary>
        /// The domain is not a Public Suffix Domain, it is the Organizational Domain for itself and its subdomains ("n").
        /// </summary>
        No
    }
}
