namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Defines the types of canonicalization used in DKIM (DomainKeys Identified Mail).
    /// Canonicalization determines how email headers and body content are normalized before signing.
    /// </summary>
    public enum CanonicalizationType
    {
        /// <summary>
        /// The "Simple" canonicalization applies minimal transformations,
        /// preserving whitespace and line breaks as they appear in the original message.
        /// </summary>
        Simple,

        /// <summary>
        /// The "Relaxed" canonicalization applies normalization,
        /// such as collapsing whitespace and standardizing header field names.
        /// This makes the signature more tolerant to minor formatting changes.
        /// </summary>
        Relaxed
    }
}
