namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Dmarc Record
    /// </summary>
    public class DmarcRecord
    {
        /// <summary>
        /// Gets or sets the DMARC version (e.g., "DMARC1").
        /// </summary>
        public required string Version { get; set; }

        /// <summary>
        /// Gets or sets the policy for the domain <see cref="DmarcPolicy"/>
        /// </summary>
        public DmarcPolicy DomainPolicy { get; set; }

        /// <summary>
        /// Gets or sets the policy for subdomains <see cref="DmarcPolicy"/>
        /// </summary>
        public DmarcPolicy SubdomainPolicy { get; set; }

        ///// <summary>
        ///// Gets or sets the URI for aggregate reports (e.g., "mailto:aggregate@example.com").
        ///// </summary>
        //public string? AggregateReportUri { get; set; }

        ///// <summary>
        ///// Gets or sets the URI for forensic reports (e.g., "mailto:forensic@example.com").
        ///// </summary>
        //public string? ForensicReportUri { get; set; }

        ///// <summary>
        ///// Gets or sets the format of reports (e.g., "afrf").
        ///// </summary>
        //public string? ReportFormat { get; set; }

        /// <summary>
        /// Gets or sets the reporting interval (e.g., "86400").
        /// </summary>
        public TimeSpan ReportingInterval { get; set; }

        ///// <summary>
        ///// Gets or sets the DKIM alignment mode (e.g., "r" for relaxed, "s" for strict).
        ///// </summary>
        //public string? DkimAlignmentMode { get; set; }

        ///// <summary>
        ///// Gets or sets the failure reporting options (e.g., "0", "1").
        ///// </summary>
        //public string? FailureReportingOptions { get; set; }

        ///// <summary>
        ///// Gets or sets the SPF alignment mode (e.g., "r" for relaxed, "s" for strict").
        ///// </summary>
        //public string? SpfAlignmentMode { get; set; }

        ///// <summary>
        ///// Gets or sets the percentage of messages subjected to the DMARC policy (e.g., "100").
        ///// </summary>
        //public string? PolicyPercentage { get; set; }
    }
}
