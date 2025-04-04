namespace Nager.EmailAuthentication.Models.Dmarc
{
    /// <summary>
    /// Represents a parsed DMARC record with its components.
    /// </summary>
    public class DmarcRecordDataFragmentBase
    {
        /// <summary>
        /// Gets or sets the DMARC version (e.g., "DMARC1").
        /// </summary>
        public string? Version { get; set; }
    }
}
