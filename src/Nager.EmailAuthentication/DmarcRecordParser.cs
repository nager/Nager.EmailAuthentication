using Nager.EmailAuthentication.Models;
using System.Diagnostics.CodeAnalysis;

namespace Nager.EmailAuthentication
{
    /// <summary>
    /// Dmarc Record Parser
    /// </summary>
    public static class DmarcRecordParser
    {
        public static bool TryParse(
            string? dmarcRaw,
            [NotNullWhen(true)] out DmarcRecord? dmarcRecord)
        {
            if (!DmarcRecordDataFragmentParser.TryParse(dmarcRaw, out var dataFragment, out _))
            {
                dmarcRecord = null;
                return false;
            }

            return TryParse(dataFragment, out dmarcRecord);
        }

        public static bool TryParse(
            string? dmarcRaw,
            [NotNullWhen(true)] out DmarcRecord? dmarcRecord,
            out ParsingResult[]? parsingResults)
        {
            if (!DmarcRecordDataFragmentParser.TryParse(dmarcRaw, out var dataFragment, out parsingResults))
            {
                dmarcRecord = null;
                return false;
            }

            return TryParse(dataFragment, out dmarcRecord);
        }

        public static bool TryParse(
            DmarcRecordDataFragment dmarcDataFragment,
            [NotNullWhen(true)] out DmarcRecord? dmarcRecord)
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

            var tempDmarcRecord = new DmarcRecord()
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
