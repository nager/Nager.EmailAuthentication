using Nager.EmailAuthentication.Models;
using System.Diagnostics.CodeAnalysis;

namespace Nager.EmailAuthentication
{
    /// <summary>
    /// Dkim Public Key Record Parser
    /// </summary>
    public static class DkimPublicKeyRecordParser
    {
        /// <summary>
        /// TryParse
        /// </summary>
        /// <param name="dkimPublicKeyRecordRaw"></param>
        /// <param name="dkimPublicKeyRecord"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimPublicKeyRecordRaw,
            [NotNullWhen(true)] out DkimPublicKeyRecord? dkimPublicKeyRecord)
        {
            if (!DkimPublicKeyRecordDataFragmentParser.TryParse(dkimPublicKeyRecordRaw, out var dataFragment, out _))
            {
                dkimPublicKeyRecord = null;
                return false;
            }

            return TryParse(dataFragment, out dkimPublicKeyRecord);
        }

        /// <summary>
        /// TryParse
        /// </summary>
        /// <param name="dkimPublicKeyRecordRaw"></param>
        /// <param name="dkimPublicKeyRecord"></param>
        /// <param name="parsingResults"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimPublicKeyRecordRaw,
            [NotNullWhen(true)] out DkimPublicKeyRecord? dkimPublicKeyRecord,
            out ParsingResult[]? parsingResults)
        {
            if (!DkimPublicKeyRecordDataFragmentParser.TryParse(dkimPublicKeyRecordRaw, out var dataFragment, out parsingResults))
            {
                dkimPublicKeyRecord = null;
                return false;
            }

            return TryParse(dataFragment, out dkimPublicKeyRecord);
        }

        /// <summary>
        /// TryParse
        /// </summary>
        /// <param name="dkimPublicKeyRecordDataFragment"></param>
        /// <param name="dkimPublicKeyRecord"></param>
        /// <returns></returns>
        public static bool TryParse(
            DkimPublicKeyRecordDataFragment? dkimPublicKeyRecordDataFragment,
            [NotNullWhen(true)] out DkimPublicKeyRecord? dkimPublicKeyRecord)
        {
            dkimPublicKeyRecord = null;

            if (dkimPublicKeyRecordDataFragment == null)
            {
                return false;
            }

            dkimPublicKeyRecord = new DkimPublicKeyRecord
            {
                Version = dkimPublicKeyRecordDataFragment.Version ?? "DKIM1",
                KeyType = dkimPublicKeyRecordDataFragment.KeyType ?? "rsa",
                PublicKeyData = dkimPublicKeyRecordDataFragment.PublicKeyData ?? string.Empty,
                Notes = dkimPublicKeyRecordDataFragment.Notes,
                Flags = dkimPublicKeyRecordDataFragment.Flags,
            };

            return true;
        }
    }
}
