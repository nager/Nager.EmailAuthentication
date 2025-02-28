using Nager.EmailAuthentication.Handlers;
using Nager.EmailAuthentication.Models;
using Nager.EmailAuthentication.RegexProviders;
using System.Diagnostics.CodeAnalysis;

namespace Nager.EmailAuthentication.FragmentParsers
{
    /// <summary>
    /// Dkim Signature Data Fragment Parser
    /// </summary>
    public static class DkimSignatureDataFragmentParserV1
    {
        /// <summary>
        /// Try Parse
        /// </summary>
        /// <param name="dkimSignature"></param>
        /// <param name="dkimSignatureDataFragment"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimSignature,
            [NotNullWhen(true)] out DkimSignatureDataFragmentV1? dkimSignatureDataFragment)
        {
            return TryParse(dkimSignature, out dkimSignatureDataFragment, out _);
        }

        /// <summary>
        /// Try Parse
        /// </summary>
        /// <param name="dkimSignature"></param>
        /// <param name="dkimSignatureDataFragment"></param>
        /// <param name="parsingResults"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? dkimSignature,
            [NotNullWhen(true)] out DkimSignatureDataFragmentV1? dkimSignatureDataFragment,
            out ParsingResult[]? parsingResults)
        {
            if (string.IsNullOrWhiteSpace(dkimSignature))
            {
                parsingResults = null;
                dkimSignatureDataFragment = null;

                return false;
            }

            var handlers = new Dictionary<string, MappingHandler<DkimSignatureDataFragmentV1>>
            {
                {
                    "v", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.Version = value,
                        Validate = ValidateVersion
                    }
                },
                {
                    "a", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.SignatureAlgorithm = value,
                        Validate = ValidateSignatureAlgorithm
                    }
                },
                {
                    "b", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.SignatureData = value
                    }
                },
                {
                    "bh", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.BodyHash = value
                    }
                },
                {
                    "c", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.MessageCanonicalization = value
                        //TODO: Add validate logic
                    }
                },
                {
                    "d", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.SigningDomainIdentifier = value,
                        Validate = ValidateDomain
                    }
                },
                {
                    "l", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.BodyLengthCount = value,
                        Validate = ValidateBodyLengthCount
                    }
                },
                {
                    "s", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.Selector = value,
                        Validate = ValidateSelector
                    }
                },
                {
                    "t", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.Timestamp = value,
                        Validate = ValidateTimestamp
                    }
                },
                {
                    "x", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.SignatureExpiration = value
                    }
                },
                {
                    "h", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.SignedHeaderFields = value,
                        Validate = ValidateSignedHeaderFields
                    }
                },
                {
                    "q", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.QueryMethods = value
                    }
                },
                {
                    "i", new MappingHandler<DkimSignatureDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.AgentOrUserIdentifier = value
                    }
                }
            };

            var parserBase = new KeyValueParserBase<DkimSignatureDataFragmentV1>(handlers);
            return parserBase.TryParse(dkimSignature, out dkimSignatureDataFragment, out parsingResults);
        }

        private static ParsingResult[] ValidatePositiveNumber(
            ValidateRequest validateRequest,
            Func<ValidateRequest, int, ParsingResult?> additionalCheck)
        {
            var parsingResults = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Is empty"
                });

                return [.. parsingResults];
            }

            if (!int.TryParse(validateRequest.Value, out var number))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Value is not a number"
                });

                return [.. parsingResults];
            }

            if (int.IsNegative(number))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Number is negative"
                });

                return [.. parsingResults];
            }

            var parsingResult = additionalCheck(validateRequest, number);
            if (parsingResult != null)
            {
                parsingResults.Add(parsingResult);

                return [.. parsingResults];
            }

            return [];
        }

        private static ParsingResult[] ValidateVersion(ValidateRequest validateRequest)
        {
            static ParsingResult? CheckVersion(ValidateRequest validateRequest, int number)
            {
                if (number == 1)
                {
                    return null;
                }

                return new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Version is invalid"
                };
            };

            return ValidatePositiveNumber(validateRequest, CheckVersion);
        }

        private static ParsingResult[] ValidateTimestamp(ValidateRequest validateRequest)
        {
            static ParsingResult? CheckTimestamp(ValidateRequest validateRequest, int number)
            {
                var timestamp = DateTimeOffset.FromUnixTimeSeconds(number);
                if (timestamp < DateTime.UtcNow)
                {
                    return null;
                }

                return new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = $"The provided timestamp '{number}' is in the future"
                };
            };

            return ValidatePositiveNumber(validateRequest, CheckTimestamp);
        }

        private static ParsingResult[] ValidateSignatureAlgorithm(ValidateRequest validateRequest)
        {
            var parsingResults = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Is empty"
                });

                return [.. parsingResults];
            }

            if (validateRequest.Value.Equals("rsa-sha256", StringComparison.OrdinalIgnoreCase))
            {
                return [];
            }
            else if (validateRequest.Value.Equals("ed25519-sha256", StringComparison.OrdinalIgnoreCase))
            {
                return [];
            }
            else if (validateRequest.Value.Equals("rsa-sha1", StringComparison.OrdinalIgnoreCase))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Warning,
                    Field = validateRequest.Field,
                    Message = "RSA with SHA-1 as the hash algorithm. No longer secure and should not be used."
                });

                return [.. parsingResults];
            }

            parsingResults.Add(new ParsingResult
            {
                Status = ParsingStatus.Error,
                Field = validateRequest.Field,
                Message = "Unknown hash algorithm used"
            });

            return [.. parsingResults];
        }

        private static ParsingResult[] ValidateSelector(ValidateRequest validateRequest)
        {
            var parsingResults = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Is empty"
                });

                return [.. parsingResults];
            }

            var maxDnsLabelLength = 63;
            if (validateRequest.Value.Length > maxDnsLabelLength)
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Selector name length limit reached"
                });
            }

            if (!DkimSelectorRegexProvider.GetRegex().IsMatch(validateRequest.Value))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Selector syntax invalid"
                });
            }

            return [.. parsingResults];
        }

        private static ParsingResult[] ValidateDomain(ValidateRequest validateRequest)
        {
            var parsingResults = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Is empty"
                });

                return [.. parsingResults];
            }

            if (!Uri.TryCreate($"https://{validateRequest.Value}", UriKind.Absolute, out _))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Critical,
                    Field = validateRequest.Field,
                    Message = "Invalid domain syntax"
                });
            }

            return [.. parsingResults];
        }

        private static ParsingResult[] ValidateBodyLengthCount(ValidateRequest validateRequest)
        {
            static ParsingResult? CheckBodyLengthCount(ValidateRequest validateRequest, int number)
            {
                if (number == 0)
                {
                    return new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = "The entire body of the email has been ignored."
                    };
                }

                return new ParsingResult
                {
                    Status = ParsingStatus.Warning,
                    Field = validateRequest.Field,
                    Message = "Manipulation of the content is possible if the length is defined for the check. The recommendation is not to set a length."
                };
            };

            return ValidatePositiveNumber(validateRequest, CheckBodyLengthCount);
        }

        private static ParsingResult[] ValidateSignedHeaderFields(ValidateRequest validateRequest)
        {
            var parsingResults = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "The signed header fields is empty, from is required"
                });

                return [.. parsingResults];
            }

            if (!validateRequest.Value.Contains(':'))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Info,
                    Field = validateRequest.Field,
                    Message = "No colon separator found"
                });
            }

            var parts = validateRequest.Value.Split(':');

            //TODO: check that headers are signed at most twice (only oversigning)
            //https://security.stackexchange.com/questions/265408/how-many-times-need-e-mail-headers-be-signed-with-dkim-to-mitigate-dkim-header-i#:~:text=If%20the%20e%2Dmail%20uses,field%20of%20the%20DKIM%20signature.
            var groupedHeaders = parts.GroupBy(o => o).Select(g => new { g.Key, Count = g.Count() });
            foreach (var groupedHeader in groupedHeaders)
            {
                if (groupedHeader.Count == 2)
                {
                    parsingResults.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Info,
                        Field = validateRequest.Field,
                        Message = $"{groupedHeader.Key} oversigning detected"
                    });
                }
            }

            var recommendedHeaders = new string[] { "from", "to", "subject", "reply-to", "date", "cc", "content-type" };
            var missingRecommendedHeaders = recommendedHeaders.Except(groupedHeaders.Select(o => o.Key));
            foreach (var missingRecommendedHeader in missingRecommendedHeaders)
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Warning,
                    Field = validateRequest.Field,
                    Message = $"Missing recommended header detected '{missingRecommendedHeader}'"
                });
            }

            return [.. parsingResults];
        }
    }
}
