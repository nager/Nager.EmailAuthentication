namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Dkim Signature Base
    /// </summary>
    public class DkimSignatureBase
    {
        /// <summary>
        /// Dkim Version <strong>(v=)</strong>
        /// </summary>
        public required string Version { get; set; }
    }
}
