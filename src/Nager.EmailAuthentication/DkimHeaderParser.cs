using Nager.EmailAuthentication.Models;

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
            out ParseError[]? parseErrors)
        {   
            var dataFragment = new DkimHeaderDataFragment();

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
                        Map = (dataFragment, value) => dataFragment.Selector = value
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
                        Map = (dataFragment, value) => dataFragment.SignedHeaderFields = value
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
            return parserBase.TryParse(dkimHeader, out dkimHeaderDataFragment, out parseErrors);
        }

        private static ParseError[] ValidatePositiveNumber(ValidateRequest validateRequest)
        {
            var errors = new List<ParseError>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Error,
                    ErrorMessage = $"{validateRequest.Field} is empty"
                });

                return [.. errors];
            }

            if (!int.TryParse(validateRequest.Value, out var reportInterval))
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Error,
                    ErrorMessage = $"{validateRequest.Field} value is not a number"
                });

                return [.. errors];
            }

            if (int.IsNegative(reportInterval))
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Error,
                    ErrorMessage = $"{validateRequest.Field} number is negative"
                });

                return [.. errors];
            }

            return [];
        }

        private static ParseError[] ValidateSignatureAlgorithm(ValidateRequest validateRequest)
        {
            var errors = new List<ParseError>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Error,
                    ErrorMessage = $"{validateRequest.Field} is empty"
                });

                return [.. errors];
            }

            if (!validateRequest.Value.StartsWith("rsa-", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Error,
                    ErrorMessage = $"{validateRequest.Field} starts not with rsa-"
                });

                return [.. errors];
            }

            return [];
        }
    }
}
