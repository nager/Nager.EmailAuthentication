namespace Nager.EmailAuthentication.Models.Dkim
{
    /// <summary>
    /// Represents the base class for DKIM signatures, which can be extended by specific versions like <see cref="DkimSignatureV1"/>.
    /// </summary>
    public class DkimSignatureBase
    {
        /// <summary>
        /// Dkim Version <strong>(v=)</strong>
        /// </summary>
        public required string Version { get; set; }
    }
}
