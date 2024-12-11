using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication
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
        /// <param name="parseErrors">A list of errors in the DMARC string, if any.</param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string dmarcRaw,
            out DmarcDataFragment? dmarcDataFragment,
            out ParseError[]? parseErrors)
        {
            parseErrors = null;

            var errors = new List<ParseError>();

            if (string.IsNullOrWhiteSpace(dmarcRaw))
            {
                dmarcDataFragment = null;
                return false;
            }

            if (!dmarcRaw.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Critical,
                    ErrorMessage = "DMARC record is invalid: it must start with 'v=DMARC1'."
                });
            }

            var keyValueSeperator = '=';
            var keyValueParser = new KeyValueParser.MemoryEfficientKeyValueParser(';', keyValueSeperator);
            if (!keyValueParser.TryParse(dmarcRaw, out var parseResult))
            {
                dmarcDataFragment = null;
                return false;
            }

            if (parseResult == null)
            {
                dmarcDataFragment = null;
                return false;
            }

            var duplicateConfigurations = parseResult.KeyValues
                .GroupBy(o => o.Key)
                .Where(g => g.Count() > 1);

            foreach (var duplicate in duplicateConfigurations)
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Error,
                    ErrorMessage = $"Duplicate configuration detected for key: '{duplicate.Key}'."
                });
            }

            var dataFragment = new DmarcDataFragment();

            var handlers = new Dictionary<string, Action<string>>
            {
                { "v", value => dataFragment.Version = value },
                { "p", value => dataFragment.DomainPolicy = value },
                { "sp", value => dataFragment.SubdomainPolicy = value },
                { "rua", value => dataFragment.AggregateReportUri = value },
                { "ruf", value => dataFragment.ForensicReportUri = value },
                { "rf", value => dataFragment.ReportFormat = value },
                { "fo", value => dataFragment.FailureOptions = value },
                { "pct", value => dataFragment.PolicyPercentage = value },
                { "ri", value => dataFragment.ReportingInterval = value },
                { "adkim", value => dataFragment.DkimAlignmentMode = value },
                { "aspf", value => dataFragment.SpfAlignmentMode = value }
            };

            foreach (var keyValue in parseResult.KeyValues)
            {
                if (string.IsNullOrEmpty(keyValue.Key))
                {
                    continue;
                }

                if (handlers.TryGetValue(keyValue.Key.ToLowerInvariant(), out var handler))
                {
                    handler(keyValue.Value ?? "");
                    continue;
                }

                errors.Add(new ParseError
                {
                    ErrorMessage = $"Unrecognized Part {keyValue.Key}{keyValueSeperator}{keyValue.Value}",
                    Severity = ErrorSeverity.Warning
                });
            }

            parseErrors = errors.Count == 0 ? null : [.. errors];
            dmarcDataFragment = dataFragment;

            return true;
        }
    }
}
