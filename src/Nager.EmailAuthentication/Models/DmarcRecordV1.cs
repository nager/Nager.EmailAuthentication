namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Dmarc Record V1
    /// </summary>
    public class DmarcRecordV1 : DmarcRecordBase
    {
        /// <summary>
        /// Gets or sets the policy for the domain.
        /// </summary>
        public DmarcPolicy DomainPolicy { get; set; }

        /// <summary>
        /// Gets or sets the policy for subdomains.
        /// </summary>
        public DmarcPolicy SubdomainPolicy { get; set; }

        /// <summary>
        /// Gets or sets the URI for aggregate reports (e.g., "mailto:aggregate@example.com").
        /// </summary>
        public DmarcEmailDetail[]? AggregateReportUri { get; set; }

        /// <summary>
        /// Gets or sets the URI for forensic reports (e.g., "mailto:forensic@example.com").
        /// </summary>
        public DmarcEmailDetail[]? ForensicReportUri { get; set; }

        /// <summary>
        /// Gets or sets the format of reports (e.g., "afrf").
        /// </summary>
        public string? ReportFormat { get; set; }

        /// <summary>
        /// Gets or sets the reporting interval (e.g., "86400").
        /// </summary>
        public TimeSpan ReportingInterval { get; set; }

        /// <summary>
        /// Gets or sets the DKIM alignment mode (e.g., "r" for relaxed, "s" for strict).
        /// </summary>
        public AlignmentMode DkimAlignmentMode { get; set; } = AlignmentMode.Relaxed;

        /// <summary>
        /// Gets or sets the SPF alignment mode (e.g., "r" for relaxed, "s" for strict").
        /// </summary>
        public AlignmentMode SpfAlignmentMode { get; set; } = AlignmentMode.Relaxed;

        ///// <summary>
        ///// Gets or sets the failure reporting options (e.g., "0", "1").
        ///// </summary>
        //public string? FailureReportingOptions { get; set; }

        /// <summary>
        /// Gets or sets the percentage of messages subjected to the DMARC policy (e.g., "100").
        /// </summary>
        public int PolicyPercentage { get; set; } = 100;
    }
}
