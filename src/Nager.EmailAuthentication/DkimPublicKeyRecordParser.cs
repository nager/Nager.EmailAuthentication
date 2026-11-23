using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Helpers;
using Nager.EmailAuthentication.Models;
using Nager.EmailAuthentication.Models.Dkim;
using System.Diagnostics.CodeAnalysis;

namespace Nager.EmailAuthentication
{
    /// <summary>
    /// Dkim Public Key Record Parser
    /// </summary>
    public static class DkimPublicKeyRecordParser
    {
        private static bool ValidateRaw(string? dkimPublicKeyRecordRaw)
        {
            if (string.IsNullOrWhiteSpace(dkimPublicKeyRecordRaw))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Try Parse
        /// </summary>
        /// <param name="dkimPublicKeyRecordRaw"></param>
        /// <param name="dkimPublicKeyRecord"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimPublicKeyRecordRaw,
            [NotNullWhen(true)] out DkimPublicKeyRecordBase? dkimPublicKeyRecord)
        {
            if (!ValidateRaw(dkimPublicKeyRecordRaw))
            {
                dkimPublicKeyRecord = null;
                return false;
            }

            if (DkimPublicKeyRecordDataFragmentParserV1.TryParse(dkimPublicKeyRecordRaw, out var dataFragment, out _))
            {
                if (dataFragment is DkimPublicKeyRecordDataFragmentV1 dataFragmentV1)
                {
                    if (TryParseV1(dataFragmentV1, out var dkimPublicKeyRecordV1))
                    {
                        dkimPublicKeyRecord = dkimPublicKeyRecordV1;
                        return true;
                    }
                }
            }

            dkimPublicKeyRecord = null;
            return false;
        }

        /// <summary>
        /// Try Parse
        /// </summary>
        /// <param name="dkimPublicKeyRecordRaw"></param>
        /// <param name="dkimPublicKeyRecord"></param>
        /// <param name="parsingResults"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimPublicKeyRecordRaw,
            [NotNullWhen(true)] out DkimPublicKeyRecordBase? dkimPublicKeyRecord,
            out ParsingResult[]? parsingResults)
        {
            if (!ValidateRaw(dkimPublicKeyRecordRaw))
            {
                dkimPublicKeyRecord = null;
                parsingResults = null;
                return false;
            }

            if (DkimPublicKeyRecordDataFragmentParserV1.TryParse(dkimPublicKeyRecordRaw, out var dataFragment, out parsingResults))
            {
                if (dataFragment is DkimPublicKeyRecordDataFragmentV1 dataFragmentV1)
                {
                    if (TryParseV1(dataFragmentV1, out var dmarcRecordV1))
                    {
                        dkimPublicKeyRecord = dmarcRecordV1;
                        return true;
                    }
                }
            }

            dkimPublicKeyRecord = null;
            return false;
        }

        /// <summary>
        /// Attempts to convert a <see cref="DkimPublicKeyRecordDataFragmentV1"/> into a <see cref="DkimPublicKeyRecordV1"/>.
        /// </summary>
        /// <remarks>
        /// The public key (p=) is required. A record with an empty public key is a revoked key
        /// (<see cref="DkimPublicKeyRecordV1.IsRevoked"/>), a record without the tag is not a DKIM public key record.
        /// </remarks>
        /// <param name="dkimPublicKeyRecordDataFragment">The data fragment with the tags of the record.</param>
        /// <param name="dkimPublicKeyRecord">The parsed DKIM public key record, if successful.</param>
        /// <returns><see langword="true"/> if the conversion is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParseV1(
            DkimPublicKeyRecordDataFragmentV1? dkimPublicKeyRecordDataFragment,
            [NotNullWhen(true)] out DkimPublicKeyRecordV1? dkimPublicKeyRecord)
        {
            dkimPublicKeyRecord = null;

            if (dkimPublicKeyRecordDataFragment == null)
            {
                return false;
            }

            if (!string.IsNullOrEmpty(dkimPublicKeyRecordDataFragment.Version) &&
                !dkimPublicKeyRecordDataFragment.Version.Equals("DKIM1", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // The public key is required (RFC 6376 section 3.6.1)
            if (dkimPublicKeyRecordDataFragment.PublicKeyData == null)
            {
                return false;
            }

            dkimPublicKeyRecord = new DkimPublicKeyRecordV1
            {
                Version = dkimPublicKeyRecordDataFragment.Version ?? "DKIM1",
                KeyType = dkimPublicKeyRecordDataFragment.KeyType ?? "rsa",
                PublicKeyData = dkimPublicKeyRecordDataFragment.PublicKeyData,
                Notes = dkimPublicKeyRecordDataFragment.Notes,
                Flags = dkimPublicKeyRecordDataFragment.Flags,
                AcceptableHashAlgorithms = dkimPublicKeyRecordDataFragment.AcceptableHashAlgorithms,
                ServiceType = dkimPublicKeyRecordDataFragment.ServiceType ?? "*"
            };

            if (DkimPublicKeyHelper.TryGetKeyLength(dkimPublicKeyRecord.KeyType, dkimPublicKeyRecord.PublicKeyData, out var keyLength))
            {
                dkimPublicKeyRecord.KeyLength = keyLength;
            }

            return true;
        }
    }
}
