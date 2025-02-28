namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Represents the DKIM signature for version 1 (v=1), inheriting from <see cref="DkimSignatureBase"/>
    /// </summary>
    public class DkimSignatureV1 : DkimSignatureBase
    {
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
        /// Body length count <strong>(l=)</strong><br/>
        /// This tag informs the Verifier of the number of octets in the body of the email after canonicalization
        /// included in the cryptographic hash, starting from 0 immediately following the CRLF preceding the body.
        /// </summary>
        public int? BodyLengthCount { get; set; }

        /// <summary>
        /// Header Message canonicalization <strong>(c=)</strong>
        /// </summary>
        public required CanonicalizationType MessageCanonicalizationHeader { get; set; }

        /// <summary>
        /// Body Message canonicalization <strong>(c=)</strong>
        /// </summary>
        public required CanonicalizationType MessageCanonicalizationBody { get; set; }

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
