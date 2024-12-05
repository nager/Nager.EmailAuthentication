using System.Text;

namespace Nager.MailAuth.Models
{
    /// <summary>
    /// Represents a parsed DMARC record with its components.
    /// </summary>
    public class DmarcDataFragment
    {
        /// <summary>
        /// Gets or sets the DMARC version (e.g., "DMARC1").
        /// </summary>
        public string? Version { get; set; }

        /// <summary>
        /// Gets or sets the policy for the domain (e.g., "none", "quarantine", "reject").
        /// </summary>
        public string? DomainPolicy { get; set; }

        /// <summary>
        /// Gets or sets the policy for subdomains (e.g., "none", "quarantine", "reject").
        /// </summary>
        public string? SubdomainPolicy { get; set; }

        /// <summary>
        /// Gets or sets the URI for aggregate reports (e.g., "mailto:aggregate@example.com").
        /// </summary>
        public string? AggregateReportUri { get; set; }

        /// <summary>
        /// Gets or sets the URI for forensic reports (e.g., "mailto:forensic@example.com").
        /// </summary>
        public string? ForensicReportUri { get; set; }

        /// <summary>
        /// Gets or sets the format of reports (e.g., "afrf").
        /// </summary>
        public string? ReportFormat { get; set; }

        /// <summary>
        /// Gets or sets the reporting interval in seconds (e.g., "86400").
        /// </summary>
        public string? ReportingInterval { get; set; }

        /// <summary>
        /// Gets or sets the DKIM alignment mode (e.g., "r" for relaxed, "s" for strict).
        /// </summary>
        public string? DkimAlignmentMode { get; set; }

        /// <summary>
        /// Gets or sets the failure reporting options (e.g., "0", "1").
        /// </summary>
        public string? FailureOptions { get; set; }

        /// <summary>
        /// Gets or sets the SPF alignment mode (e.g., "r" for relaxed, "s" for strict").
        /// </summary>
        public string? SpfAlignmentMode { get; set; }

        /// <summary>
        /// Gets or sets the percentage of messages subjected to the DMARC policy (e.g., "100").
        /// </summary>
        public string? PolicyPercentage { get; set; }

        /// <summary>
        /// Returns a string representation of the DMARC record in a valid DMARC format.
        /// </summary>
        /// <returns>A string representing the DMARC record.</returns>
        public override string ToString()
        {
            var builder = new StringBuilder();

            builder.Append($"v={Version}; p={DomainPolicy}");

            if (!string.IsNullOrWhiteSpace(SubdomainPolicy))
            {
                builder.Append($"; sp={SubdomainPolicy}");
            }
            if (!string.IsNullOrWhiteSpace(AggregateReportUri))
            {
                builder.Append($"; rua={AggregateReportUri}");
            }
            if (!string.IsNullOrWhiteSpace(ForensicReportUri))
            {
                builder.Append($"; ruf={ForensicReportUri}");
            }
            if (!string.IsNullOrWhiteSpace(ReportFormat))
            {
                builder.Append($"; rf={ReportFormat}");
            }
            if (!string.IsNullOrWhiteSpace(ReportingInterval))
            {
                builder.Append($"; ri={ReportingInterval}");
            }
            if (!string.IsNullOrWhiteSpace(DkimAlignmentMode))
            {
                builder.Append($"; adkim={DkimAlignmentMode}");
            }
            if (!string.IsNullOrWhiteSpace(FailureOptions))
            {
                builder.Append($"; fo={FailureOptions}");
            }
            if (!string.IsNullOrWhiteSpace(SpfAlignmentMode))
            {
                builder.Append($"; aspf={SpfAlignmentMode}");
            }
            if (!string.IsNullOrWhiteSpace(PolicyPercentage))
            {
                builder.Append($"; pct={PolicyPercentage}");
            }

            builder.Append(';');

            return builder.ToString();
        }
    }
}
