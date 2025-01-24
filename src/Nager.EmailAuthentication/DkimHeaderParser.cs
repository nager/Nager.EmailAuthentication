﻿using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication
{
    public static class DkimHeaderParser
    {
        public static bool TryParse(
            string dkimHeader,
            out DkimHeaderDataFragment? dkimHeaderDataFragment)
        {
            return TryParse(dkimHeader, out dkimHeaderDataFragment, out _);
        }

        public static bool TryParse(
            string dkimHeader,
            out DkimHeaderDataFragment? dkimHeaderDataFragment,
            out ParsingResult[]? parsingResults)
        {
            var handlers = new Dictionary<string, MappingHandler<DkimHeaderDataFragment>>
            {
                {
                    "v", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Version = value,
                        Validate = ValidatePositiveNumber
                    }
                },
                {
                    "a", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.SignatureAlgorithm = value,
                        Validate = ValidateSignatureAlgorithm
                    }
                },
                {
                    "b", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.SignatureData = value
                    }
                },
                {
                    "bh", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.BodyHash = value
                    }
                },
                {
                    "c", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.MessageCanonicalization = value
                    }
                },
                {
                    "d", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Domain = value
                    }
                },
                {
                    "s", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Selector = value,
                        Validate = ValidateSelector
                    }
                },
                {
                    "t", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Timestamp = value,
                        Validate = ValidatePositiveNumber
                    }
                },
                {
                    "x", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.SignatureExpiration = value
                    }
                },
                {
                    "h", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.SignedHeaderFields = value,
                        Validate = ValidateSignedHeaderFields
                    }
                },
                {
                    "q", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.QueryMethods = value
                    }
                },
                {
                    "i", new MappingHandler<DkimHeaderDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.AgentOrUserIdentifier = value
                    }
                }
            };

            var parserBase = new KeyValueParserBase<DkimHeaderDataFragment>(handlers);
            return parserBase.TryParse(dkimHeader, out dkimHeaderDataFragment, out parsingResults);
        }

        private static ParsingResult[] ValidatePositiveNumber(ValidateRequest validateRequest)
        {
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Message = $"{validateRequest.Field} is empty"
                });

                return [.. errors];
            }

            if (!int.TryParse(validateRequest.Value, out var reportInterval))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Message = $"{validateRequest.Field} value is not a number"
                });

                return [.. errors];
            }

            if (int.IsNegative(reportInterval))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Message = $"{validateRequest.Field} number is negative"
                });

                return [.. errors];
            }

            return [];
        }

        private static ParsingResult[] ValidateSignatureAlgorithm(ValidateRequest validateRequest)
        {
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Message = $"{validateRequest.Field} is empty"
                });

                return [.. errors];
            }

            if (!validateRequest.Value.StartsWith("rsa-", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Message = $"{validateRequest.Field} starts not with rsa-"
                });

                return [.. errors];
            }

            return [];
        }

        private static ParsingResult[] ValidateSelector(ValidateRequest validateRequest)
        {
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Message = $"{validateRequest.Field} is empty"
                });

                return [.. errors];
            }

            var maxDnsLabelLength = 63;
            if (validateRequest.Value.Length > maxDnsLabelLength)
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Message = $"selector name length limit reached"
                });
            }

            return [.. errors];
        }

        private static ParsingResult[] ValidateSignedHeaderFields(ValidateRequest validateRequest)
        {
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Message = $"{validateRequest.Field} is empty"
                });

                return [.. errors];
            }

            var importantHeaders = new string[] { "from", "to", "subject" };

            var colonIndex = validateRequest.Value.IndexOf(':');
            if (colonIndex == -1)
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Message = $"{validateRequest.Field} no colon found"
                });

                return [.. errors];
            }

            var parts = validateRequest.Value.Split(':');

            //https://security.stackexchange.com/questions/265408/how-many-times-need-e-mail-headers-be-signed-with-dkim-to-mitigate-dkim-header-i#:~:text=If%20the%20e%2Dmail%20uses,field%20of%20the%20DKIM%20signature.
            var groupedHeaders = parts.GroupBy(o => o).Select(g => new { Key = g.Key, Count = g.Count() });
            foreach (var groupedHeader in groupedHeaders)
            {
                if (groupedHeader.Count == 2)
                {
                    errors.Add(new ParsingResult { Status = ParsingStatus.Info, Message = $"{groupedHeader.Key} oversigning detected" });
                }
            }

            //TODO: Check important Headers
            //TODO: check that headers are signed at most twice (only oversigning)

            return [.. errors];
        }
    }
}
