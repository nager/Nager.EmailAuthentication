namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Dkim Signature
    /// </summary>
    public class DkimSignature
    {
        /// <summary>
        /// Dkim Version <strong>(v=)</strong>
        /// </summary>
        public required string Version { get; set; }

        /// <summary>
        /// Dkim Signature Algorithm <strong>(a=)</strong>
        /// </summary>
        public SignatureAlgorithm SignatureAlgorithm { get; set; }

        /// <summary>
        /// Signature data <strong>(b=)</strong>
        /// </summary>
        public required string SignatureData { get; set; }

        /// <summary>
        /// Body hash <strong>(bh=)</strong>
        /// </summary>
        public required string BodyHash { get; set; }

        /// <summary>
        /// Message canonicalization <strong>(c=)</strong>
        /// </summary>
        public required string MessageCanonicalization { get; set; }

        /// <summary>
        /// Signing Domain Identifier <strong>(d=)</strong>
        /// </summary>
        public required string SigningDomainIdentifier { get; set; }

        /// <summary>
        /// Selector <strong>(s=)</strong>
        /// </summary>
        public required string Selector { get; set; }

        /// <summary>
        /// Signature Timestamp <strong>(t=)</strong>
        /// </summary>
        public DateTimeOffset? Timestamp { get; set; }

        /// <summary>
        /// Signature Expiration <strong>(x=)</strong>
        /// </summary>
        public DateTimeOffset? SignatureExpiration { get; set; }

        /// <summary>
        /// Signed header fields <strong>(h=)</strong>
        /// </summary>
        public string[] SignedHeaderFields { get; set; } = [];

        /// <summary>
        /// Query Methods, default is "dns/txt" <strong>(q=)</strong>
        /// </summary>
        public string? QueryMethods { get; set; }

        /// <summary>
        /// The Agent or User Identifier <strong>(i=)</strong>
        /// </summary>
        public string? AgentOrUserIdentifier { get; set; }
    }
}
