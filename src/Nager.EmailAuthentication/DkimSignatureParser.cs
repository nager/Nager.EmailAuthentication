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
        /// Try Parse
        /// </summary>
        /// <param name="dkimSignatureRaw"></param>
        /// <param name="dkimSignature"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimSignatureRaw,
            [NotNullWhen(true)] out DkimSignatureBase? dkimSignature)
        {
            if (!DkimSignatureDataFragmentParser.TryParse(dkimSignatureRaw, out var dataFragment, out _))
            {
                dkimSignature = null;
                return false;
            }

            if (dataFragment is DkimSignatureDataFragmentV1 dataFragmentV1)
            {
                if (TryParseV1(dataFragmentV1, out var dkimSignatureV1))
                {
                    dkimSignature = dkimSignatureV1;
                    return true;
                }
            }

            dkimSignature = null;
            return false;
        }

        /// <summary>
        /// Try Parse
        /// </summary>
        /// <param name="dkimSignatureRaw"></param>
        /// <param name="dkimSignature"></param>
        /// <param name="parsingResults"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimSignatureRaw,
            [NotNullWhen(true)] out DkimSignatureBase? dkimSignature,
            out ParsingResult[]? parsingResults)
        {
            if (!DkimSignatureDataFragmentParser.TryParse(dkimSignatureRaw, out var dataFragment, out parsingResults))
            {
                dkimSignature = null;
                return false;
            }

            if (dataFragment is DkimSignatureDataFragmentV1 dataFragmentV1)
            {
                if (TryParseV1(dataFragmentV1, out var dkimSignatureV1))
                {
                    dkimSignature = dkimSignatureV1;
                    return true;
                }
            }

            dkimSignature = null;
            return false;
        }

        /// <summary>
        /// Try Parse V1
        /// </summary>
        /// <param name="dkimSignatureDataFragment"></param>
        /// <param name="dkimSignature"></param>
        /// <returns></returns>
        public static bool TryParseV1(
            DkimSignatureDataFragmentV1? dkimSignatureDataFragment,
            [NotNullWhen(true)] out DkimSignatureV1? dkimSignature)
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

            if (!TryGetSignatureAlgorithm(dkimSignatureDataFragment.SignatureAlgorithm, out var signatureAlgorithm))
            {
                return false;
            }

            _ = TryParseUnixTimestamp(dkimSignatureDataFragment.Timestamp, out var timestamp);
            _ = TryParseUnixTimestamp(dkimSignatureDataFragment.SignatureExpiration, out var signatureExpiration);

            int? bodyLengthCount = null;
            if (!string.IsNullOrEmpty(dkimSignatureDataFragment.BodyLengthCount))
            {
                if (!int.TryParse(dkimSignatureDataFragment.BodyLengthCount, out var tempBodyLengthCount))
                {
                    return false;
                }

                bodyLengthCount = tempBodyLengthCount;
            }

            var messageCanonicalizationHeader = CanonicalizationType.Simple;
            var messageCanonicalizationBody = CanonicalizationType.Simple;

            if (!string.IsNullOrEmpty(dkimSignatureDataFragment.MessageCanonicalization))
            {
                var parts = dkimSignatureDataFragment.MessageCanonicalization.Split('/');

                if (parts.Length >= 1)
                {
                    if (TryGetCanonicalizationType(parts[0], out var canonicalizationType))
                    {
                        messageCanonicalizationHeader = canonicalizationType.Value;
                    }
                    else
                    {
                        return false;
                    }
                }

                if (parts.Length == 2)
                {
                    if (TryGetCanonicalizationType(parts[1], out var canonicalizationType))
                    {
                        messageCanonicalizationBody = canonicalizationType.Value;
                    }
                    else
                    {
                        return false;
                    }
                }

                if (parts.Length > 2)
                {
                    return false;
                }
            }

            var signedHeaders = dkimSignatureDataFragment.SignedHeaderFields.Split(':', StringSplitOptions.TrimEntries);

            dkimSignature = new DkimSignatureV1
            {
                Version = dkimSignatureDataFragment.Version,
                SigningDomainIdentifier = dkimSignatureDataFragment.SigningDomainIdentifier.Trim(' ', '\t'),
                Selector = dkimSignatureDataFragment.Selector.Trim(' ', '\t'),
                BodyHash = dkimSignatureDataFragment.BodyHash,
                BodyLengthCount = bodyLengthCount,
                QueryMethods = dkimSignatureDataFragment.QueryMethods,
                SignatureData = dkimSignatureDataFragment.SignatureData,
                SignatureAlgorithm = signatureAlgorithm.Value,
                SignatureExpiration = signatureExpiration,
                AgentOrUserIdentifier = dkimSignatureDataFragment.AgentOrUserIdentifier,
                SignedHeaderFields = signedHeaders,
                MessageCanonicalizationHeader = messageCanonicalizationHeader,
                MessageCanonicalizationBody = messageCanonicalizationBody,
                Timestamp = timestamp
            };

            return true;
        }

        private static bool TryGetCanonicalizationType(
            string canonicalizationTypeRaw,
            [NotNullWhen(true)] out CanonicalizationType? canonicalizationType)
        {
            if (canonicalizationTypeRaw.Equals("relaxed", StringComparison.OrdinalIgnoreCase))
            {
                canonicalizationType = CanonicalizationType.Relaxed;
                return true;
            }
            else if (canonicalizationTypeRaw.Equals("simple", StringComparison.OrdinalIgnoreCase))
            {
                canonicalizationType = CanonicalizationType.Simple;
                return true;
            }

            canonicalizationType = null;
            return false;
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
            else if (signatureAlgorithmRaw.Equals("ed25519-sha256", StringComparison.OrdinalIgnoreCase))
            {
                signatureAlgorithm = SignatureAlgorithm.Ed25519Sha256;
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
