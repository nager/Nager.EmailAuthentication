namespace Nager.EmailAuthentication.Models.Dmarc
{
    /// <summary>
    /// Defines the alignment mode for DMARC (Domain-based Message Authentication, Reporting, and Conformance).
    /// The alignment mode determines how strictly the domain in the "From" header must match the domains in SPF and DKIM.
    /// </summary>
    public enum AlignmentMode
    {
        /// <summary>
        /// The relaxed mode allows subdomains to pass alignment checks.
        /// </summary>
        Relaxed,

        /// <summary>
        /// The strict mode requires an exact match between the domain in the "From" header and the authenticated domain.
        /// </summary>
        Strict
    }
}
