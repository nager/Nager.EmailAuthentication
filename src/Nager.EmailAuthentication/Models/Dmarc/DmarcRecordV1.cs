namespace Nager.EmailAuthentication.Models.Dmarc
{
    /// <summary>
    /// Dmarc Record V1, interpreted as defined by RFC 9989 (obsoletes RFC 7489)
    /// </summary>
    public class DmarcRecordV1 : DmarcRecordBase
    {
        /// <summary>
        /// Gets or sets the policy for the domain.
        /// </summary>
        public DmarcPolicy DomainPolicy { get; set; }

        /// <summary>
        /// Gets or sets the policy for existing subdomains.
        /// If the record has no "sp" tag, this is the policy for the domain.
        /// </summary>
        public DmarcPolicy SubdomainPolicy { get; set; }

        /// <summary>
        /// Gets or sets the policy for non-existent subdomains.
        /// If the record has no "np" tag, this is the policy for subdomains.
        /// </summary>
        public DmarcPolicy NonExistentSubdomainPolicy { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the record is in test mode ("t=y").
        /// In test mode the policy that is applied to failing messages is one level below the specified policy
        /// ("reject" is applied as "quarantine", "quarantine" as "none").
        /// </summary>
        public bool TestMode { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the record is published for a Public Suffix Domain.
        /// </summary>
        public PublicSuffixDomainMode PublicSuffixDomain { get; set; } = PublicSuffixDomainMode.Unknown;

        /// <summary>
        /// Gets or sets the URI for aggregate reports (e.g., "mailto:aggregate@example.com").
        /// Contains only the "mailto:" URIs of the record, mail receivers ignore other URIs.
        /// </summary>
        public DmarcEmailDetail[]? AggregateReportUri { get; set; }

        /// <summary>
        /// Gets or sets the URI for forensic reports (e.g., "mailto:forensic@example.com").
        /// Contains only the "mailto:" URIs of the record, mail receivers ignore other URIs.
        /// </summary>
        public DmarcEmailDetail[]? ForensicReportUri { get; set; }

        /// <summary>
        /// Gets or sets the format of reports (e.g., "afrf").
        /// The "rf" tag is obsolete, it was removed by RFC 9989.
        /// </summary>
        public string? ReportFormat { get; set; }

        /// <summary>
        /// Gets or sets the reporting interval (e.g., "86400").
        /// The "ri" tag is obsolete, it was removed by RFC 9989.
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
        /// The "pct" tag is obsolete, it was removed by RFC 9989 and replaced by the test mode ("t").
        /// </summary>
        public int PolicyPercentage { get; set; } = 100;
    }
}
