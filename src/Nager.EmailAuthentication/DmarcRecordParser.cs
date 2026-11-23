using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Models;
using Nager.EmailAuthentication.Models.Dmarc;
using System.Diagnostics.CodeAnalysis;

namespace Nager.EmailAuthentication
{
    /// <summary>
    /// Dmarc Record Parser
    /// </summary>
    public static class DmarcRecordParser
    {
        private const string DmarcVersion = "DMARC1";

        /// <summary>
        /// Determines whether a TXT record is a DMARC record: it starts with the version tag "v=DMARC1".
        /// The value of the version tag is case sensitive, whitespace around the equal sign is allowed (RFC 9989 section 4.7 and 4.8).
        /// Records that do not start with the version tag are ignored by mail receivers.
        /// </summary>
        /// <param name="txtRecord">The content of a TXT record.</param>
        /// <returns><c>true</c> if the record starts with the DMARC version tag; otherwise, <c>false</c>.</returns>
        public static bool IsDmarcRecord([NotNullWhen(true)] string? txtRecord)
        {
            var remaining = txtRecord.AsSpan().TrimStart();
            if (remaining.Length == 0 || (remaining[0] != 'v' && remaining[0] != 'V'))
            {
                return false;
            }

            remaining = remaining[1..].TrimStart();
            if (remaining.Length == 0 || remaining[0] != '=')
            {
                return false;
            }

            remaining = remaining[1..].TrimStart();
            if (!remaining.StartsWith(DmarcVersion, StringComparison.Ordinal))
            {
                return false;
            }

            remaining = remaining[DmarcVersion.Length..].TrimStart();
            return remaining.Length == 0 || remaining[0] == ';';
        }

        /// <summary>
        /// Attempts to parse a raw DMARC record string into a <see cref="DmarcRecordBase"/> object.
        /// </summary>
        /// <param name="dmarcRaw">The raw DMARC record string to be parsed.</param>
        /// <param name="dmarcRecord">
        /// When this method returns, contains the parsed <see cref="DmarcRecordBase"/> if the parsing succeeded; 
        /// otherwise, <c>null</c>.
        /// </param>
        /// <returns>
        /// <c>true</c> if the parsing was successful (i.e., mail receivers can apply the record); 
        /// otherwise, <c>false</c>.
        /// </returns>
        public static bool TryParse(
            string? dmarcRaw,
            [NotNullWhen(true)] out DmarcRecordBase? dmarcRecord)
        {
            return TryParse(dmarcRaw, out dmarcRecord, out _);
        }

        /// <summary>
        /// Attempts to parse a raw DMARC record string into a <see cref="DmarcRecordBase"/> object while also 
        /// returning additional parsing details.
        /// </summary>
        /// <remarks>
        /// The record is interpreted like a mail receiver does (RFC 9989): unknown tags and tags with an invalid value
        /// are ignored in favor of their default value and reported in <paramref name="parsingResults"/>.
        /// The parsing only fails if mail receivers ignore the whole record.
        /// </remarks>
        /// <param name="dmarcRaw">The raw DMARC record string to be parsed.</param>
        /// <param name="dmarcRecord">
        /// When this method returns, contains the parsed <see cref="DmarcRecordBase"/> if the parsing succeeded; 
        /// otherwise, <c>null</c>.
        /// </param>
        /// <param name="parsingResults">
        /// When this method returns, contains an array of <see cref="ParsingResult"/> objects with additional details 
        /// (such as errors, warnings or informational messages) regarding the parsing process. This value may be <c>null</c>
        /// if the parsing did not occur or there are no details.
        /// </param>
        /// <returns>
        /// <c>true</c> if the parsing was successful; otherwise, <c>false</c>.
        /// </returns>
        public static bool TryParse(
            string? dmarcRaw,
            [NotNullWhen(true)] out DmarcRecordBase? dmarcRecord,
            out ParsingResult[]? parsingResults)
        {
            dmarcRecord = null;

            if (!IsDmarcRecord(dmarcRaw))
            {
                parsingResults = null;
                return false;
            }

            if (!DmarcRecordDataFragmentParserV1.TryParse(dmarcRaw, out var dataFragment, out parsingResults))
            {
                return false;
            }

            var isSuccessful = TryParseV1(dataFragment, out var dmarcRecordV1, out var recordParsingResults);
            if (recordParsingResults != null)
            {
                parsingResults = [.. parsingResults ?? [], .. recordParsingResults];
            }

            dmarcRecord = dmarcRecordV1;
            return isSuccessful;
        }

        /// <summary>
        /// Attempts to convert a <see cref="DmarcRecordDataFragmentV1"/> into a <see cref="DmarcRecordV1"/>.
        /// </summary>
        /// <param name="dmarcDataFragment">
        /// The <see cref="DmarcRecordDataFragmentV1"/> containing individual DMARC parameter strings to be parsed.
        /// </param>
        /// <param name="dmarcRecord">
        /// When this method returns, contains the parsed <see cref="DmarcRecordV1"/> if successful; 
        /// otherwise, <c>null</c>.
        /// </param>
        /// <returns>
        /// <c>true</c> if the conversion was successful; otherwise, <c>false</c>.
        /// </returns>
        public static bool TryParseV1(
            DmarcRecordDataFragmentV1 dmarcDataFragment,
            [NotNullWhen(true)] out DmarcRecordV1? dmarcRecord)
        {
            return TryParseV1(dmarcDataFragment, out dmarcRecord, out _);
        }

        /// <summary>
        /// Attempts to convert a <see cref="DmarcRecordDataFragmentV1"/> into a <see cref="DmarcRecordV1"/>
        /// the way a mail receiver interprets the record (RFC 9989).
        /// </summary>
        /// <remarks>
        /// Tags with an invalid value are ignored in favor of their default value (RFC 9989 section 4.8).
        /// A record without a valid policy ("p", "sp" and "np") is treated like "p=none" if it has a valid URI
        /// for aggregate reports, otherwise mail receivers ignore it and the conversion fails (RFC 9989 section 4.10.1).
        /// </remarks>
        /// <param name="dmarcDataFragment">
        /// The <see cref="DmarcRecordDataFragmentV1"/> containing individual DMARC parameter strings to be parsed.
        /// </param>
        /// <param name="dmarcRecord">
        /// When this method returns, contains the parsed <see cref="DmarcRecordV1"/> if successful; 
        /// otherwise, <c>null</c>.
        /// </param>
        /// <param name="parsingResults">
        /// When this method returns, contains the findings that concern the record as a whole, e.g. a missing policy.
        /// This value is <c>null</c> if there are none. Findings for single tags are reported by
        /// <see cref="DmarcRecordDataFragmentParserV1"/>.
        /// </param>
        /// <returns>
        /// <c>true</c> if the conversion was successful; otherwise, <c>false</c>.
        /// </returns>
        public static bool TryParseV1(
            DmarcRecordDataFragmentV1 dmarcDataFragment,
            [NotNullWhen(true)] out DmarcRecordV1? dmarcRecord,
            out ParsingResult[]? parsingResults)
        {
            dmarcRecord = null;
            parsingResults = null;

            if (!DmarcVersion.Equals(dmarcDataFragment.Version, StringComparison.Ordinal))
            {
                return false;
            }

            var tempDmarcRecord = new DmarcRecordV1()
            {
                Version = dmarcDataFragment.Version,
                AggregateReportUri = GetEmailDetails(dmarcDataFragment.AggregateReportUri),
                ForensicReportUri = GetEmailDetails(dmarcDataFragment.ForensicReportUri),
                TestMode = "y".Equals(dmarcDataFragment.TestMode, StringComparison.OrdinalIgnoreCase)
            };

            var hasDomainPolicy = TryGetDmarcPolicy(dmarcDataFragment.DomainPolicy, out var domainPolicy);
            var hasValidSubdomainPolicy = TryGetOptionalDmarcPolicy(dmarcDataFragment.SubdomainPolicy, out var subdomainPolicy);
            var hasValidNonExistentSubdomainPolicy = TryGetOptionalDmarcPolicy(dmarcDataFragment.NonExistentSubdomainPolicy, out var nonExistentSubdomainPolicy);

            if (hasDomainPolicy && hasValidSubdomainPolicy && hasValidNonExistentSubdomainPolicy)
            {
                tempDmarcRecord.DomainPolicy = domainPolicy!.Value;
                tempDmarcRecord.SubdomainPolicy = subdomainPolicy ?? tempDmarcRecord.DomainPolicy;
                tempDmarcRecord.NonExistentSubdomainPolicy = nonExistentSubdomainPolicy ?? tempDmarcRecord.SubdomainPolicy;
            }
            else
            {
                var invalidTag = !hasDomainPolicy ? "p" : !hasValidSubdomainPolicy ? "sp" : "np";
                var hasAggregateReportUri = tempDmarcRecord.AggregateReportUri?.Any(o => o.IsValidEmailAddress) == true;

                if (!hasAggregateReportUri)
                {
                    parsingResults =
                    [
                        new ParsingResult
                        {
                            Status = ParsingStatus.Critical,
                            Field = invalidTag,
                            Message = "No valid policy and no valid URI for aggregate reports, mail receivers ignore the record"
                        }
                    ];

                    return false;
                }

                parsingResults =
                [
                    new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = invalidTag,
                        Message = "No valid policy, mail receivers treat the record like 'p=none'"
                    }
                ];

                tempDmarcRecord.DomainPolicy = DmarcPolicy.None;
                tempDmarcRecord.SubdomainPolicy = DmarcPolicy.None;
                tempDmarcRecord.NonExistentSubdomainPolicy = DmarcPolicy.None;
            }

            tempDmarcRecord.PublicSuffixDomain = dmarcDataFragment.PublicSuffixDomain?.ToLowerInvariant() switch
            {
                "y" => PublicSuffixDomainMode.Yes,
                "n" => PublicSuffixDomainMode.No,
                _ => PublicSuffixDomainMode.Unknown
            };

            if (TryGetAlignmentMode(dmarcDataFragment.DkimAlignmentMode, out var dkimAlignmentMode))
            {
                tempDmarcRecord.DkimAlignmentMode = dkimAlignmentMode.Value;
            }

            if (TryGetAlignmentMode(dmarcDataFragment.SpfAlignmentMode, out var spfAlignmentMode))
            {
                tempDmarcRecord.SpfAlignmentMode = spfAlignmentMode.Value;
            }

            // Obsolete tags of RFC 7489, an invalid value does not affect the record
            tempDmarcRecord.ReportingInterval = TryGetReportingInterval(dmarcDataFragment.ReportingInterval, out var reportingInterval)
                ? reportingInterval.Value
                : TimeSpan.FromSeconds(86400);

            tempDmarcRecord.PolicyPercentage = TryGetPolicyPercentage(dmarcDataFragment.PolicyPercentage, out var policyPercentage)
                ? policyPercentage.Value
                : 100;

            tempDmarcRecord.ReportFormat = "afrf".Equals(dmarcDataFragment.ReportFormat, StringComparison.OrdinalIgnoreCase)
                ? dmarcDataFragment.ReportFormat
                : "afrf";

            dmarcRecord = tempDmarcRecord;
            return true;
        }

        /// <summary>
        /// Returns the "mailto:" URIs of a "rua" or "ruf" tag. Mail receivers ignore URIs they do not support
        /// and URIs with a syntax error.
        /// </summary>
        private static DmarcEmailDetail[]? GetEmailDetails(string? input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return null;
            }

            var details = new List<DmarcEmailDetail>();

            foreach (var part in input.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                if (DmarcEmailDetail.TryParse(part, out var emailDetail))
                {
                    details.Add(emailDetail);
                }
            }

            return details.Count > 0 ? [.. details] : null;
        }

        private static bool TryGetAlignmentMode(
            string? input,
            [NotNullWhen(true)] out AlignmentMode? alignmentMode)
        {
            if (string.IsNullOrEmpty(input))
            {
                alignmentMode = null;
                return false;
            }

            if (input.Equals("s", StringComparison.OrdinalIgnoreCase))
            {
                alignmentMode = AlignmentMode.Strict;
                return true;
            }

            if (input.Equals("r", StringComparison.OrdinalIgnoreCase))
            {
                alignmentMode = AlignmentMode.Relaxed;
                return true;
            }

            alignmentMode = null;
            return false;
        }

        private static bool TryGetPolicyPercentage(
            string? input,
            [NotNullWhen(true)] out int? policyPercentage)
        {
            if (string.IsNullOrEmpty(input))
            {
                policyPercentage = 100;
                return true;
            }

            if (!int.TryParse(input, out var tempPolicyPercentage))
            {
                policyPercentage = null;
                return false;
            }

            if (int.IsNegative(tempPolicyPercentage))
            {
                policyPercentage = null;
                return false;
            }

            if (tempPolicyPercentage > 100)
            {
                policyPercentage = null;
                return false;
            }

            policyPercentage = tempPolicyPercentage;
            return true;
        }

        private static bool TryGetReportingInterval(
            string? input,
            [NotNullWhen(true)] out TimeSpan? reportingInterval)
        {
            if (string.IsNullOrEmpty(input))
            {
                reportingInterval = TimeSpan.FromSeconds(86400);
                return true;
            }

            if (!int.TryParse(input, out var intervalInSeconds))
            {
                reportingInterval = null;
                return false;
            }

            if (int.IsNegative(intervalInSeconds))
            {
                reportingInterval = null;
                return false;
            }

            reportingInterval = TimeSpan.FromSeconds(intervalInSeconds);
            return true;
        }

        /// <summary>
        /// Policy of an optional tag ("sp" and "np")
        /// </summary>
        /// <returns><c>false</c> if the tag has a value that is not a policy</returns>
        private static bool TryGetOptionalDmarcPolicy(
            string? input,
            out DmarcPolicy? dmarcPolicy)
        {
            if (string.IsNullOrEmpty(input))
            {
                dmarcPolicy = null;
                return true;
            }

            return TryGetDmarcPolicy(input, out dmarcPolicy);
        }

        private static bool TryGetDmarcPolicy(
            string? input,
            [NotNullWhen(true)] out DmarcPolicy? dmarcPolicy)
        {
            dmarcPolicy = input?.ToLowerInvariant() switch
            {
                "none" => DmarcPolicy.None,
                "quarantine" => DmarcPolicy.Quarantine,
                "reject" => DmarcPolicy.Reject,
                _ => null
            };

            return dmarcPolicy != null;
        }
    }
}
