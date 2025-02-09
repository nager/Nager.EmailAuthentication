namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Signature Algorithm
    /// </summary>
    public enum SignatureAlgorithm
    {
        /// <summary>
        /// RSA SHA-1
        /// </summary>
        RsaSha1,

        /// <summary>
        ///  RSA SHA-256
        /// </summary>
        RsaSha256,

        /// <summary>
        /// Ed25519 with SHA-256
        /// </summary>
        Ed25519Sha256
    }
}
