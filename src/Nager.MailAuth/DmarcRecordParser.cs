using Nager.MailAuth.Models;

namespace Nager.MailAuth
{
    /// <summary>
    /// Dmarc Record Parser
    /// </summary>
    public static class DmarcRecordParser
    {
        /// <summary>
        /// Attempts to parse a raw DMARC string into a <see cref="DmarcDataFragment"/> object.
        /// </summary>
        /// <param name="dmarcRaw">The raw DMARC string to parse.</param>
        /// <param name="dmarcDataFragment">The parsed DMARC record, if successful.</param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string dmarcRaw,
            out DmarcDataFragment? dmarcDataFragment)
        {
            return TryParse(dmarcRaw, out dmarcDataFragment, out _);
        }

        /// <summary>
        /// Attempts to parse a raw DMARC string into a <see cref="DmarcDataFragment"/> object.
        /// </summary>
        /// <param name="dmarcRaw">The raw DMARC string to parse.</param>
        /// <param name="dmarcDataFragment">The parsed DMARC record, if successful.</param>
        /// <param name="unrecognizedParts">A list of unrecognized parts in the DMARC string, if any.</param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string dmarcRaw,
            out DmarcDataFragment? dmarcDataFragment,
            out string[]? unrecognizedParts)
        {
            unrecognizedParts = null;

            if (string.IsNullOrWhiteSpace(dmarcRaw))
            {
                dmarcDataFragment = null;
                return false;
            }

            var dataFragment = new DmarcDataFragment();
            var internalUnrecognizedParts = new List<string>();

            var handlers = new Dictionary<string, Action<string>>
            {
                { "v=", value => dataFragment.Version = value },
                { "p=", value => dataFragment.DomainPolicy = value },
                { "sp=", value => dataFragment.SubdomainPolicy = value },
                { "rua=", value => dataFragment.AggregateReportUri = value },
                { "ruf=", value => dataFragment.ForensicReportUri = value },
                { "rf=", value => dataFragment.ReportFormat = value },
                { "fo=", value => dataFragment.FailureOptions = value },
                { "pct=", value => dataFragment.PolicyPercentage = value },
                { "ri=", value => dataFragment.ReportingInterval = value },
                { "adkim=", value => dataFragment.DkimAlignmentMode = value },
                { "aspf=", value => dataFragment.SpfAlignmentMode = value }
            };

            var parts = dmarcRaw.Split(";", StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts)
            {
                var cleanPart = part.AsSpan().TrimStart(' ');
                var keyValueSeparatorIndex = cleanPart.IndexOf('=');

                if (keyValueSeparatorIndex <= 0)
                {
                    internalUnrecognizedParts.Add(cleanPart.ToString());
                    continue;
                }

                var key = cleanPart[..(keyValueSeparatorIndex + 1)];
                var value = cleanPart[(keyValueSeparatorIndex + 1)..];

                if (handlers.TryGetValue(key.ToString().ToLowerInvariant(), out var handler))
                {
                    handler(value.ToString());
                    continue;
                }

                internalUnrecognizedParts.Add(cleanPart.ToString());
            }

            if (internalUnrecognizedParts.Count > 0)
            {
                unrecognizedParts = [.. internalUnrecognizedParts];
            }

            dmarcDataFragment = dataFragment;

            return true;
        }
    }
}
