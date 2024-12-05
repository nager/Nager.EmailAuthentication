using Nager.MailAuth.Models;

namespace Nager.MailAuth
{
    /// <summary>
    /// Dmarc Record Parser
    /// </summary>
    public static class DmarcRecordParser
    {
        /// <summary>
        /// Attempts to parse a raw DMARC string into a <see cref="DmarcRecord"/> object.
        /// </summary>
        /// <param name="dmarcRaw">The raw DMARC string to parse.</param>
        /// <param name="dmarcRecord">The parsed DMARC record, if successful.</param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string dmarcRaw,
            out DmarcRecord? dmarcRecord)
        {
            return TryParse(dmarcRaw, out dmarcRecord, out _);
        }

        /// <summary>
        /// Attempts to parse a raw DMARC string into a <see cref="DmarcRecord"/> object.
        /// </summary>
        /// <param name="dmarcRaw">The raw DMARC string to parse.</param>
        /// <param name="dmarcRecord">The parsed DMARC record, if successful.</param>
        /// <param name="unrecognizedParts">A list of unrecognized parts in the DMARC string, if any.</param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string dmarcRaw,
            out DmarcRecord? dmarcRecord,
            out string[]? unrecognizedParts)
        {
            unrecognizedParts = null;

            if (string.IsNullOrWhiteSpace(dmarcRaw))
            {
                dmarcRecord = null;
                return false;
            }

            var internalDmarcRecord = new DmarcRecord();
            var internalUnrecognizedParts = new List<string>();

            var handlers = new Dictionary<string, Action<string>>
            {
                { "v=", value => internalDmarcRecord.Version = value },
                { "p=", value => internalDmarcRecord.DomainPolicy = value },
                { "sp=", value => internalDmarcRecord.SubdomainPolicy = value },
                { "rua=", value => internalDmarcRecord.AggregateReportUri = value },
                { "ruf=", value => internalDmarcRecord.ForensicReportUri = value },
                { "rf=", value => internalDmarcRecord.ReportFormat = value },
                { "fo=", value => internalDmarcRecord.FailureOptions = value },
                { "pct=", value => internalDmarcRecord.PolicyPercentage = value },
                { "ri=", value => internalDmarcRecord.ReportingInterval = value },
                { "adkim=", value => internalDmarcRecord.DkimAlignmentMode = value },
                { "aspf=", value => internalDmarcRecord.SpfAlignmentMode = value }
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

            dmarcRecord = internalDmarcRecord;

            return true;
        }
    }
}
