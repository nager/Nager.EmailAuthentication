namespace Nager.EmailAuthentication.Models.Dmarc
{
    /// <summary>
    /// Dmarc Record Base
    /// </summary>
    public class DmarcRecordBase
    {
        /// <summary>
        /// Gets or sets the DMARC version (e.g., "DMARC1").
        /// </summary>
        public required string Version { get; set; }
    }
}
