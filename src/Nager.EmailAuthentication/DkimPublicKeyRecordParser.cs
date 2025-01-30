using Nager.EmailAuthentication.Handlers;
using Nager.EmailAuthentication.Models;
using System.Buffers.Text;
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
        /// <param name="dkimPublicKeyRecord"></param>
        /// <param name="dkimPublicKeyRecordDataFragment"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimPublicKeyRecord,
            [NotNullWhen(true)] out DkimPublicKeyRecordDataFragment? dkimPublicKeyRecordDataFragment)
        {
            return TryParse(dkimPublicKeyRecord, out dkimPublicKeyRecordDataFragment, out _);
        }

        /// <summary>
        /// TryParse
        /// </summary>
        /// <param name="dkimPublicKeyRecord"></param>
        /// <param name="dkimPublicKeyRecordDataFragment"></param>
        /// <param name="parsingResults"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimPublicKeyRecord,
            [NotNullWhen(true)] out DkimPublicKeyRecordDataFragment? dkimPublicKeyRecordDataFragment,
            out ParsingResult[]? parsingResults)
        {
            if (string.IsNullOrWhiteSpace(dkimPublicKeyRecord))
            {
                parsingResults = null;
                dkimPublicKeyRecordDataFragment = null;

                return false;
            }

            var handlers = new Dictionary<string, MappingHandler<DkimPublicKeyRecordDataFragment>>
            {
                {
                    "p", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.PublicKeyData = value,
                        Validate = ValidatePublicKeyData
                    }
                },
                {
                    "v", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Version = value,
                        Validate = ValidateVersion
                    }
                },
                {
                    "k", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.KeyType = value,
                        Validate = ValidateKeyType
                    }
                },
                {
                    "n", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Notes = value
                    }
                },
                {
                    "t", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Flags = value
                    }
                },
                {
                    "g", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Granularity = value,
                        Validate = ValidateGranularity
                    }
                }
            };

            var parserBase = new KeyValueParserBase<DkimPublicKeyRecordDataFragment>(handlers);
            return parserBase.TryParse(dkimPublicKeyRecord, out dkimPublicKeyRecordDataFragment, out parsingResults);
        }

        private static ParsingResult[] ValidatePublicKeyData(ValidateRequest validateRequest)
        {
            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                return
                [
                    new ParsingResult
                    {
                        Status = ParsingStatus.Critical,
                        Message = "Public key data is emtpty"
                    }
                ];
            }

            if (Base64.IsValid(validateRequest.Value))
            {
                return [];
            }

            return
            [
                new ParsingResult
                {
                    Status = ParsingStatus.Critical,
                    Message = "Invalid Public Key data, not base64 encoded"
                }
            ];
        }

        private static ParsingResult[] ValidateVersion(ValidateRequest validateRequest)
        {
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                return [
                    new ParsingResult
                    {
                        Status = ParsingStatus.Critical,
                        Message = "DKIM record is invalid: it must start with 'v=DKIM1' if it specified"
                    }
                ];
            }

            if (validateRequest.Value.Equals("DKIM1", StringComparison.OrdinalIgnoreCase))
            {
                return [];
            }

            return [
                new ParsingResult
                {
                    Status = ParsingStatus.Critical,
                    Message = "DKIM record is invalid: it must start with 'v=DKIM1'."
                }
            ];
        }

        private static ParsingResult[] ValidateGranularity(ValidateRequest validateRequest)
        {
            return
            [
                new ParsingResult
                {
                    Status = ParsingStatus.Warning,
                    Message = "Granularity is deprecated."
                }
            ];
        }

        private static ParsingResult[] ValidateKeyType(ValidateRequest validateRequest)
        {
            var allowedKeyTypes = new string[] { "rsa", "ed25519" };

            if (allowedKeyTypes.Contains(validateRequest.Value, StringComparer.CurrentCultureIgnoreCase))
            {
                return [];
            }

            return
            [
                new ParsingResult
                {
                    Status = ParsingStatus.Critical,
                    Message = "The type of the key is invalid"
                }
            ];
        }
    }
}
