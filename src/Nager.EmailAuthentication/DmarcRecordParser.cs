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
        private static bool ValidateRaw(string? dmarcRaw)
        {
            if (string.IsNullOrWhiteSpace(dmarcRaw))
            {
                return false;
            }

            if (!dmarcRaw.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return true;
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
        /// <c>true</c> if the parsing was successful (i.e., all required fields are present and valid); 
        /// otherwise, <c>false</c>.
        /// </returns>
        public static bool TryParse(
            string? dmarcRaw,
            [NotNullWhen(true)] out DmarcRecordBase? dmarcRecord)
        {
            if (!ValidateRaw(dmarcRaw))
            {
                dmarcRecord = null;
                return false;
            }

            if (DmarcRecordDataFragmentParserV1.TryParse(dmarcRaw, out var dataFragment, out _))
            {
                if (dataFragment is DmarcRecordDataFragmentV1 dataFragmentV1)
                {
                    if (TryParseV1(dataFragmentV1, out var dmarcRecordV1))
                    {
                        dmarcRecord = dmarcRecordV1;
                        return true;
                    }
                }
            }

            dmarcRecord = null;
            return false;
        }

        /// <summary>
        /// Attempts to parse a raw DMARC record string into a <see cref="DmarcRecordBase"/> object while also 
        /// returning additional parsing details.
        /// </summary>
        /// <param name="dmarcRaw">The raw DMARC record string to be parsed.</param>
        /// <param name="dmarcRecord">
        /// When this method returns, contains the parsed <see cref="DmarcRecordBase"/> if the parsing succeeded; 
        /// otherwise, <c>null</c>.
        /// </param>
        /// <param name="parsingResults">
        /// When this method returns, contains an array of <see cref="ParsingResult"/> objects with additional details 
        /// (such as warnings or informational messages) regarding the parsing process. This value may be <c>null</c>
        /// if the parsing did not occur.
        /// </param>
        /// <returns>
        /// <c>true</c> if the parsing was successful; otherwise, <c>false</c>.
        /// </returns>
        public static bool TryParse(
            string? dmarcRaw,
            [NotNullWhen(true)] out DmarcRecordBase? dmarcRecord,
            out ParsingResult[]? parsingResults)
        {
            if (!ValidateRaw(dmarcRaw))
            {
                dmarcRecord = null;
                parsingResults = null;
                return false;
            }

            if (DmarcRecordDataFragmentParserV1.TryParse(dmarcRaw, out var dataFragment, out parsingResults))
            {
                if (dataFragment is DmarcRecordDataFragmentV1 dataFragmentV1)
                {
                    if (TryParseV1(dataFragmentV1, out var dmarcRecordV1))
                    {
                        dmarcRecord = dmarcRecordV1;
                        return true;
                    }
                }
            }

            dmarcRecord = null;
            return false;
        }

        /// <summary>
        /// Attempts to convert a <see cref="DmarcRecordDataFragmentV1"/> into a fully validated 
        /// <see cref="DmarcRecordV1"/> by parsing and validating all required DMARC fields.
        /// </summary>
        /// <param name="dmarcDataFragment">
        /// The <see cref="DmarcRecordDataFragmentV1"/> containing individual DMARC parameter strings to be parsed.
        /// </param>
        /// <param name="dmarcRecord">
        /// When this method returns, contains the parsed and validated <see cref="DmarcRecordV1"/> if successful; 
        /// otherwise, <c>null</c>.
        /// </param>
        /// <returns>
        /// <c>true</c> if the conversion and validation were successful; otherwise, <c>false</c>.
        /// </returns>
        public static bool TryParseV1(
            DmarcRecordDataFragmentV1 dmarcDataFragment,
            [NotNullWhen(true)] out DmarcRecordV1? dmarcRecord)
        {
            dmarcRecord = null;

            if (string.IsNullOrEmpty(dmarcDataFragment.Version))
            {
                return false;
            }

            if (!dmarcDataFragment.Version.Equals("DMARC1", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var tempDmarcRecord = new DmarcRecordV1()
            {
                Version = dmarcDataFragment.Version
            };

            if (string.IsNullOrEmpty(dmarcDataFragment.DomainPolicy))
            {
                return false;
            }

            if (!TryGetDmarcPolicy(dmarcDataFragment.DomainPolicy, out var domainDmarcPolicy))
            {
                return false;
            }

            tempDmarcRecord.DomainPolicy = domainDmarcPolicy.Value;
            tempDmarcRecord.SubdomainPolicy = domainDmarcPolicy.Value;

            if (!string.IsNullOrEmpty(dmarcDataFragment.SubdomainPolicy))
            {
                if (!TryGetDmarcPolicy(dmarcDataFragment.SubdomainPolicy, out var subdomainDmarcPolicy))
                {
                    return false;
                }

                tempDmarcRecord.SubdomainPolicy = subdomainDmarcPolicy.Value;
            }

            if (!TryGetReportingInterval(dmarcDataFragment.ReportingInterval, out var reportingInterval))
            {
                return false;
            }
            tempDmarcRecord.ReportingInterval = reportingInterval.Value;

            if (!TryGetPolicyPercentage(dmarcDataFragment.PolicyPercentage, out var policyPercentage))
            {
                return false;
            }
            tempDmarcRecord.PolicyPercentage = policyPercentage.Value;

            if (dmarcDataFragment.ReportFormat == null)
            {
                tempDmarcRecord.ReportFormat = "afrf";
            }
            else
            {
                if (!dmarcDataFragment.ReportFormat.Equals("afrf", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                tempDmarcRecord.ReportFormat = dmarcDataFragment.ReportFormat;
            }

            if (dmarcDataFragment.DkimAlignmentMode != null)
            {
                if (!TryGetAlignmentMode(dmarcDataFragment.DkimAlignmentMode, out var dkimAlignmentMode))
                {
                    return false;
                }
                tempDmarcRecord.DkimAlignmentMode = dkimAlignmentMode.Value;
            }

            if (dmarcDataFragment.SpfAlignmentMode != null)
            {
                if (!TryGetAlignmentMode(dmarcDataFragment.SpfAlignmentMode, out var spfAlignmentMode))
                {
                    return false;
                }
                tempDmarcRecord.SpfAlignmentMode = spfAlignmentMode.Value;
            }

            if (!string.IsNullOrEmpty(dmarcDataFragment.AggregateReportUri))
            {
                if (!TryParseEmailDetails(dmarcDataFragment.AggregateReportUri, out var dmarcEmailDetails))
                {
                    return false;
                }

                tempDmarcRecord.AggregateReportUri = dmarcEmailDetails;
            }

            if (!string.IsNullOrEmpty(dmarcDataFragment.ForensicReportUri))
            {
                if (!TryParseEmailDetails(dmarcDataFragment.ForensicReportUri, out var dmarcEmailDetails))
                {
                    return false;
                }

                tempDmarcRecord.ForensicReportUri = dmarcEmailDetails;
            }       

            dmarcRecord = tempDmarcRecord;
            return true;
        }

        private static bool TryParseEmailDetails(
            string input,
            [NotNullWhen(true)] out DmarcEmailDetail[]? dmarcEmailDetails)
        {
            var parts = input.Split(',', StringSplitOptions.TrimEntries);
            var details = new List<DmarcEmailDetail>();

            foreach (var part in parts)
            {
                if (!DmarcEmailDetail.TryParse(part, out var emailDetail))
                {
                    dmarcEmailDetails = null;
                    return false;
                }

                details.Add(emailDetail);
            }

            dmarcEmailDetails = [.. details];
            return true;
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

        private static bool TryGetDmarcPolicy(
            string input,
            [NotNullWhen(true)] out DmarcPolicy? dmarcPolicy)
        {
            if (Enum.TryParse(input, true, out DmarcPolicy parsedPolicy))
            {
                dmarcPolicy = parsedPolicy;
                return true;
            }

            dmarcPolicy = null;
            return false;
        }
    }
}
