namespace Nager.EmailAuthentication.Models.Spf
{
    /// <summary>
    /// Represents the different types of mechanisms used in SPF (Sender Policy Framework) records.
    /// These mechanisms define the rules for which servers are authorized to send emails on behalf of a domain.
    /// </summary>
    public enum MechanismType
    {
        /// <summary>
        /// Represents an IPv4 address mechanism (`ip4`).
        /// </summary>
        Ip4,

        /// <summary>
        /// Represents an IPv6 address mechanism (`ip6`).
        /// </summary>
        Ip6,

        /// <summary>
        /// Represents an "A" record mechanism (`a`), used to authorize servers based on the domain's A or AAAA records.
        /// </summary>
        A,

        /// <summary>
        /// Represents a Mail Exchange (MX) record mechanism (`mx`), used to authorize servers based on the domain's MX records.
        /// </summary>
        Mx,

        /// <summary>
        /// Represents a PTR record mechanism (`ptr`), used to authorize servers based on reverse DNS lookups.
        /// </summary>
        Ptr,

        /// <summary>
        /// Represents an `include` mechanism, used to include the SPF record of another domain.
        /// </summary>
        Include,

        /// <summary>
        /// Represents the `exists` mechanism, used to authorize servers based on the existence of a DNS record for a domain.
        /// </summary>
        Exists,

        /// <summary>
        /// Represents the `all` mechanism, typically used at the end of the SPF record to define a catch-all rule for all other IPs.
        /// </summary>
        All
    }
}
