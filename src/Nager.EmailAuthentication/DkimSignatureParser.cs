using Nager.EmailAuthentication.Models;
using System.Diagnostics.CodeAnalysis;

namespace Nager.EmailAuthentication
{
    /// <summary>
    /// Dkim Signature Parser
    /// </summary>
    public static class DkimSignatureParser
    {
        /// <summary>
        /// TryParse
        /// </summary>
        /// <param name="dkimSignatureRaw"></param>
        /// <param name="dkimSignature"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimSignatureRaw,
            [NotNullWhen(true)] out DkimSignature? dkimSignature)
        {
            if (!DkimSignatureDataFragmentParser.TryParse(dkimSignatureRaw, out var dataFragment, out _))
            {
                dkimSignature = null;
                return false;
            }

            return TryParse(dataFragment, out dkimSignature);
        }

        /// <summary>
        /// TryParse
        /// </summary>
        /// <param name="dkimSignatureRaw"></param>
        /// <param name="dkimSignature"></param>
        /// <param name="parsingResults"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimSignatureRaw,
            [NotNullWhen(true)] out DkimSignature? dkimSignature,
            out ParsingResult[]? parsingResults)
        {
            if (!DkimSignatureDataFragmentParser.TryParse(dkimSignatureRaw, out var dataFragment, out parsingResults))
            {
                dkimSignature = null;
                return false;
            }

            return TryParse(dataFragment, out dkimSignature);
        }

        /// <summary>
        /// TryParse
        /// </summary>
        /// <param name="dkimSignatureDataFragment"></param>
        /// <param name="dkimSignature"></param>
        /// <returns></returns>
        public static bool TryParse(
            DkimSignatureDataFragment? dkimSignatureDataFragment,
            [NotNullWhen(true)] out DkimSignature? dkimSignature)
        {
            dkimSignature = null;

            if (dkimSignatureDataFragment == null)
            {
                return false;
            }

            if (string.IsNullOrEmpty(dkimSignatureDataFragment.Version))
            {
                return false;
            }

            if (string.IsNullOrEmpty(dkimSignatureDataFragment.SigningDomainIdentifier))
            {
                return false;
            }

            if (string.IsNullOrEmpty(dkimSignatureDataFragment.Selector))
            {
                return false;
            }

            if (string.IsNullOrEmpty(dkimSignatureDataFragment.SignatureData))
            {
                return false;
            }

            if (string.IsNullOrEmpty(dkimSignatureDataFragment.BodyHash))
            {
                return false;
            }

            if (string.IsNullOrEmpty(dkimSignatureDataFragment.SignedHeaderFields))
            {
                return false;
            }

            if (string.IsNullOrEmpty(dkimSignatureDataFragment.MessageCanonicalization))
            {
                return false;
            }

            if (!TryGetSignatureAlgorithm(dkimSignatureDataFragment.SignatureAlgorithm, out var signatureAlgorithm))
            {
                return false;
            }

            TryParseUnixTimestamp(dkimSignatureDataFragment.Timestamp, out var timestamp);
            TryParseUnixTimestamp(dkimSignatureDataFragment.SignatureExpiration, out var signatureExpiration);

            dkimSignature = new DkimSignature
            {
                Version = dkimSignatureDataFragment.Version,
                SigningDomainIdentifier = dkimSignatureDataFragment.SigningDomainIdentifier.Trim(' ', '\t'),
                Selector = dkimSignatureDataFragment.Selector.Trim(' ', '\t'),
                BodyHash = dkimSignatureDataFragment.BodyHash,
                QueryMethods = dkimSignatureDataFragment.QueryMethods,
                SignatureData = dkimSignatureDataFragment.SignatureData,
                SignatureAlgorithm = signatureAlgorithm.Value,
                SignatureExpiration = signatureExpiration,
                AgentOrUserIdentifier = dkimSignatureDataFragment.AgentOrUserIdentifier,
                SignedHeaderFields = dkimSignatureDataFragment.SignedHeaderFields.Split(':'),
                MessageCanonicalization = dkimSignatureDataFragment.MessageCanonicalization,
                Timestamp = timestamp
            };

            return true;
        }

        private static bool TryGetSignatureAlgorithm(
            string? signatureAlgorithmRaw,
            [NotNullWhen(true)] out SignatureAlgorithm? signatureAlgorithm)
        {
            signatureAlgorithm = null;

            if (string.IsNullOrEmpty(signatureAlgorithmRaw))
            {
                return false;
            }

            if (signatureAlgorithmRaw.Equals("rsa-sha256", StringComparison.OrdinalIgnoreCase))
            {
                signatureAlgorithm = SignatureAlgorithm.RsaSha256;
                return true;
            }
            else if (signatureAlgorithmRaw.Equals("rsa-sha1", StringComparison.OrdinalIgnoreCase))
            {
                signatureAlgorithm = SignatureAlgorithm.RsaSha1;
                return true;
            }

            return false;
        }

        private static bool TryParseUnixTimestamp(
            string? timeStampRaw,
            out DateTimeOffset? unixTimestamp)
        {
            unixTimestamp = null;

            if (string.IsNullOrEmpty(timeStampRaw))
            {
                return false;
            }

            if (!long.TryParse(timeStampRaw, out var UnixTimestampAsNumber))
            {
                return false;
            }

            try
            {
                unixTimestamp = DateTimeOffset.FromUnixTimeSeconds(UnixTimestampAsNumber);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
