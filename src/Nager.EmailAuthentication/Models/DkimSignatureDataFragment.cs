﻿namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Dkim Signature Data Fragment
    /// </summary>
    public class DkimSignatureDataFragment
    {
        /// <summary>
        /// Dkim Version <strong>(v=)</strong>
        /// </summary>
        public string? Version { get; set; }

        /// <summary>
        /// Dkim Signature Algorithm <strong>(a=)</strong>
        /// </summary>
        public string? SignatureAlgorithm { get; set; }

        /// <summary>
        /// Signature data <strong>(b=)</strong>
        /// </summary>
        public string? SignatureData { get; set; }

        /// <summary>
        /// Body hash <strong>(bh=)</strong>
        /// </summary>
        public string? BodyHash { get; set; }

        /// <summary>
        /// Message canonicalization <strong>(c=)</strong>
        /// </summary>
        public string? MessageCanonicalization { get; set; }

        /// <summary>
        /// Signing Domain Identifier SDID <strong>(d=)</strong>
        /// </summary>
        public string? SigningDomainIdentifier { get; set; }

        /// <summary>
        /// Selector <strong>(s=)</strong>
        /// </summary>
        public string? Selector { get; set; }

        /// <summary>
        /// Signature Timestamp <strong>(t=)</strong>
        /// </summary>
        public string? Timestamp { get; set; }

        /// <summary>
        /// Signature Expiration <strong>(x=)</strong>
        /// </summary>
        public string? SignatureExpiration { get; set; }

        /// <summary>
        /// Signed header fields <strong>(h=)</strong>
        /// </summary>
        public string? SignedHeaderFields { get; set; }

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
