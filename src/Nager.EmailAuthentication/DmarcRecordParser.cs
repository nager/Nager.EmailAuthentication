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

            if (!string.IsNullOrEmpty(dmarcDataFragment.Version) &&
                !dmarcDataFragment.Version.Equals("DMARC1", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var tempDmarcRecord = new DmarcRecord()
            {
                Version = dmarcDataFragment.Version!
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

            tempDmarcRecord.ReportingInterval = reportingInterval;

            dmarcRecord = tempDmarcRecord;
            return true;
        }

        private static bool TryGetReportingInterval(
            string? input,
            out TimeSpan reportingInterval)
        {
            if (string.IsNullOrEmpty(input))
            {
                reportingInterval = TimeSpan.FromSeconds(86400);
                return true;
            }

            if (!int.TryParse(input, out var intervalInSeconds))
            {
                reportingInterval = TimeSpan.Zero;
                return false;
            }

            if (int.IsNegative(intervalInSeconds))
            {
                reportingInterval = TimeSpan.Zero;
                return false;
            }

            reportingInterval = TimeSpan.FromSeconds(intervalInSeconds);
            return true;
        }

        private static bool TryGetDmarcPolicy(
            string policy,
            [NotNullWhen(true)] out DmarcPolicy? dmarcPolicy)
        {
            if (policy.Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                dmarcPolicy = DmarcPolicy.None;
                return true;
            }
            else if (policy.Equals("quarantine", StringComparison.OrdinalIgnoreCase))
            {
                dmarcPolicy = DmarcPolicy.Quarantine;
                return true;
            }
            else if (policy.Equals("reject", StringComparison.OrdinalIgnoreCase))
            {
                dmarcPolicy = DmarcPolicy.Reject;
                return true;
            }

            dmarcPolicy = null;
            return false;
        }
    }
}
