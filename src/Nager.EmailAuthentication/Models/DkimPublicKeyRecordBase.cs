namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Dkim Public Key Record
    /// </summary>
    public class DkimPublicKeyRecordBase
    {
        /// <summary>
        /// Dkim Version <strong>(v=)</strong>
        /// </summary>
        public required string Version { get; set; } = "DKIM1";
    }
}
