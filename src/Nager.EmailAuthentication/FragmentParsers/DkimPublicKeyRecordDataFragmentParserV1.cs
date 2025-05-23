﻿using Nager.EmailAuthentication.Handlers;
using Nager.EmailAuthentication.Models;
using Nager.EmailAuthentication.Models.Dkim;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;

namespace Nager.EmailAuthentication.FragmentParsers
{
    /// <summary>
    /// Dkim Public Key Record Data Fragment Parser
    /// </summary>
    public static class DkimPublicKeyRecordDataFragmentParserV1
    {
        /// <summary>
        /// Try Parse
        /// </summary>
        /// <param name="dkimPublicKeyRecord"></param>
        /// <param name="dkimPublicKeyRecordDataFragment"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimPublicKeyRecord,
            [NotNullWhen(true)] out DkimPublicKeyRecordDataFragmentV1? dkimPublicKeyRecordDataFragment)
        {
            return TryParse(dkimPublicKeyRecord, out dkimPublicKeyRecordDataFragment, out _);
        }

        /// <summary>
        /// Try Parse
        /// </summary>
        /// <param name="dkimPublicKeyRecord"></param>
        /// <param name="dkimPublicKeyRecordDataFragment"></param>
        /// <param name="parsingResults"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimPublicKeyRecord,
            [NotNullWhen(true)] out DkimPublicKeyRecordDataFragmentV1? dkimPublicKeyRecordDataFragment,
            out ParsingResult[]? parsingResults)
        {
            if (string.IsNullOrWhiteSpace(dkimPublicKeyRecord))
            {
                parsingResults = null;
                dkimPublicKeyRecordDataFragment = null;

                return false;
            }

            var handlers = new Dictionary<string, MappingHandler<DkimPublicKeyRecordDataFragmentV1>>
            {
                {
                    "p", new MappingHandler<DkimPublicKeyRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.PublicKeyData = value,
                        Validate = ValidatePublicKeyData
                    }
                },
                {
                    "v", new MappingHandler<DkimPublicKeyRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.Version = value,
                        Validate = ValidateVersion
                    }
                },
                {
                    "k", new MappingHandler<DkimPublicKeyRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.KeyType = value,
                        Validate = ValidateKeyType
                    }
                },
                {
                    "n", new MappingHandler<DkimPublicKeyRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.Notes = value
                    }
                },
                {
                    "t", new MappingHandler<DkimPublicKeyRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.Flags = value
                    }
                },
                {
                    "g", new MappingHandler<DkimPublicKeyRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.Granularity = value,
                        Validate = ValidateGranularity
                    }
                },
                {
                    "h", new MappingHandler<DkimPublicKeyRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.AcceptableHashAlgorithms = value
                    }
                },
                {
                    "s", new MappingHandler<DkimPublicKeyRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.ServiceType = value,
                        Validate = ValidateServiceType
                    }
                },
            };

            var parserBase = new KeyValueParserBase<DkimPublicKeyRecordDataFragmentV1>(handlers);
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
                        Field = validateRequest.Field,
                        Message = "Public key data is empty"
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
                    Field = validateRequest.Field,
                    Message = "Invalid Public Key data, not base64 encoded"
                }
            ];
        }

        private static ParsingResult[] ValidateVersion(ValidateRequest validateRequest)
        {
            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                return [
                    new ParsingResult
                    {
                        Status = ParsingStatus.Critical,
                        Field = validateRequest.Field,
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
                    Field = validateRequest.Field,
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
                    Field = validateRequest.Field,
                    Message = "Granularity is deprecated. Introduced in RFC 4871 and removed in RFC 6376."
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
                    Field = validateRequest.Field,
                    Message = "The type of the key is invalid"
                }
            ];
        }

        private static ParsingResult[] ValidateServiceType(ValidateRequest validateRequest)
        {
            var allowedServiceTypes = new string[] { "*", "email" };

            if (allowedServiceTypes.Contains(validateRequest.Value, StringComparer.CurrentCultureIgnoreCase))
            {
                return [];
            }

            return
            [
                new ParsingResult
                {
                    Status = ParsingStatus.Critical,
                    Field = validateRequest.Field,
                    Message = "The ServiceType is invalid"
                }
            ];
        }
    }
}
