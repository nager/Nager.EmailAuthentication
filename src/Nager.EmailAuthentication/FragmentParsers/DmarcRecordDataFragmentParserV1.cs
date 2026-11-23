using Nager.EmailAuthentication.Handlers;
using Nager.EmailAuthentication.Models;
using Nager.EmailAuthentication.Models.Dmarc;
using System.Diagnostics.CodeAnalysis;

namespace Nager.EmailAuthentication.FragmentParsers
{
    /// <summary>
    /// Dmarc Record Data Fragment Parser
    /// </summary>
    public static class DmarcRecordDataFragmentParserV1
    {
        /// <summary>
        /// Attempts to parse a raw DMARC string into a <see cref="DmarcRecordDataFragmentV1"/> object.
        /// </summary>
        /// <param name="dmarcString">The raw DMARC string to parse.</param>
        /// <param name="dmarcDataFragment">The parsed DMARC record, if successful.</param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string? dmarcString,
            [NotNullWhen(true)] out DmarcRecordDataFragmentV1? dmarcDataFragment)
        {
            return TryParse(dmarcString, out dmarcDataFragment, out _);
        }

        /// <summary>
        /// Attempts to parse a raw DMARC string into a <see cref="DmarcRecordDataFragmentV1"/> object.
        /// </summary>
        /// <param name="dmarcString">The raw DMARC string to parse.</param>
        /// <param name="dmarcDataFragment">The parsed DMARC record, if successful.</param>
        /// <param name="parsingResults">A list of errors in the DMARC string, if any.</param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string? dmarcString,
            [NotNullWhen(true)] out DmarcRecordDataFragmentV1? dmarcDataFragment,
            out ParsingResult[]? parsingResults)
        {
            if (string.IsNullOrWhiteSpace(dmarcString))
            {
                parsingResults = null;
                dmarcDataFragment = null;

                return false;
            }

            var handlers = new Dictionary<string, MappingHandler<DmarcRecordDataFragmentV1>>
            {
                {
                    "v", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.Version = value,
                        Validate = ValidateVersion
                    }
                },
                {
                    "p", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.DomainPolicy = value,
                        Validate = ValidateDomainPolicy
                    }
                },
                {
                    "sp", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.SubdomainPolicy = value,
                        Validate = ValidateDomainPolicy
                    }
                },
                {
                    "np", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.NonExistentSubdomainPolicy = value,
                        Validate = ValidateDomainPolicy
                    }
                },
                {
                    "t", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.TestMode = value,
                        Validate = ValidateTestMode
                    }
                },
                {
                    "psd", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.PublicSuffixDomain = value,
                        Validate = ValidatePublicSuffixDomain
                    }
                },
                {
                    "rua", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.AggregateReportUri = value,
                        Validate = ValidateAddresses
                    }
                },
                {
                    "ruf", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.ForensicReportUri = value,
                        Validate = ValidateAddresses
                    }
                },
                {
                    "rf", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.ReportFormat = value,
                        Validate = ValidateObsoleteTag
                    }
                },
                {
                    "fo", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.FailureReportingOptions = value,
                        Validate = ValidateFailureReportingOptions
                    }
                },
                {
                    "pct", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.PolicyPercentage = value,
                        Validate = ValidateObsoleteTag
                    }
                },
                {
                    "ri", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.ReportingInterval = value,
                        Validate = ValidateObsoleteTag
                    }
                },
                {
                    "adkim", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.DkimAlignmentMode = value,
                        Validate = ValidateAlignmentMode
                    }
                },
                {
                    "aspf", new MappingHandler<DmarcRecordDataFragmentV1>
                    {
                        Map = (dataFragment, value) => dataFragment.SpfAlignmentMode = value,
                        Validate = ValidateAlignmentMode
                    }
                }
            };

            var parserBase = new KeyValueParserBase<DmarcRecordDataFragmentV1>(handlers);
            return parserBase.TryParse(dmarcString, out dmarcDataFragment, out parsingResults);
        }

        private static ParsingResult[] ValidateVersion(ValidateRequest validateRequest)
        {
            var parsingResults = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Critical,
                    Field = validateRequest.Field,
                    Message = "DMARC record is invalid: it must start with 'v=DMARC1'."
                });

                return [.. parsingResults];
            }

            // The value of the version tag is case sensitive (RFC 9989 section 4.7)
            if (!validateRequest.Value.Equals("DMARC1", StringComparison.Ordinal))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Critical,
                    Field = validateRequest.Field,
                    Message = "DMARC record is invalid: it must start with 'v=DMARC1'."
                });
            }

            return [.. parsingResults];
        }

        private static ParsingResult[] ValidateDomainPolicy(ValidateRequest validateRequest)
        {
            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                return [];
            }

            var parsingResults = new List<ParsingResult>();
            var allowedPolicies = Enum.GetNames<DmarcPolicy>();

            var domainPolicy = allowedPolicies
                .Where(policy => policy.Equals(validateRequest.Value, StringComparison.OrdinalIgnoreCase))
                .SingleOrDefault();

            if (domainPolicy == null)
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = $"Unknown policy \"{validateRequest.Value}\""
                });
            }

            return [.. parsingResults];
        }

        /// <summary>
        /// Tags of RFC 7489 that were removed by RFC 9989 ("pct", "rf" and "ri"). Mail receivers ignore them,
        /// so the value is not validated.
        /// </summary>
        private static ParsingResult[] ValidateObsoleteTag(ValidateRequest validateRequest)
        {
            return
            [
                new ParsingResult
                {
                    Status = ParsingStatus.Warning,
                    Field = validateRequest.Field,
                    Message = "Tag is obsolete. Introduced in RFC 7489 and removed in RFC 9989."
                }
            ];
        }

        private static ParsingResult[] ValidateTestMode(ValidateRequest validateRequest)
        {
            return ValidateAllowedValues(validateRequest, "y", "n");
        }

        private static ParsingResult[] ValidatePublicSuffixDomain(ValidateRequest validateRequest)
        {
            return ValidateAllowedValues(validateRequest, "y", "n", "u");
        }

        private static ParsingResult[] ValidateAllowedValues(ValidateRequest validateRequest, params string[] allowedValues)
        {
            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                return
                [
                    new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = "Is empty"
                    }
                ];
            }

            if (!allowedValues.Contains(validateRequest.Value, StringComparer.OrdinalIgnoreCase))
            {
                return
                [
                    new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Wrong config {validateRequest.Value}"
                    }
                ];
            }

            return [];
        }

        private static ParsingResult[] ValidateFailureReportingOptions(ValidateRequest validateRequest)
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

            parsingResults.Add(new ParsingResult
            {
                Status = ParsingStatus.Info,
                Field = validateRequest.Field,
                Message = "Is not required, as failure reports are not very common"
            });

            var allowedOptions = new char[] { '0', '1', 'd', 's' };

            if (validateRequest.Value.Length == 1)
            {
                if (!allowedOptions.Contains(validateRequest.Value[0]))
                {
                    parsingResults.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Wrong config {validateRequest.Value}"
                    });
                }

                return [.. parsingResults];
            }

            if (!validateRequest.Value.Contains(':'))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "No colon separator found"
                });

                return [.. parsingResults];
            }

            var parts = validateRequest.Value.Split(':');
            foreach (var part in parts)
            {
                if (part.Length != 1)
                {
                    parsingResults.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Option invalid {part}"
                    });

                    continue;
                }

                if (!allowedOptions.Contains(part[0]))
                {
                    parsingResults.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Wrong config {part[0]}"
                    });
                }
            }

            return [.. parsingResults];
        }

        private static ParsingResult[] ValidateAlignmentMode(ValidateRequest validateRequest)
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

            var allowedOptions = new char[] { 'r', 's' };

            if (validateRequest.Value.Length == 1)
            {
                if (!allowedOptions.Contains(validateRequest.Value[0]))
                {
                    parsingResults.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Wrong config {validateRequest.Value}"
                    });
                }

                return [.. parsingResults];
            }

            parsingResults.Add(new ParsingResult
            {
                Status = ParsingStatus.Error,
                Field = validateRequest.Field,
                Message = $"Wrong config {validateRequest.Value}"
            });

            return [.. parsingResults];
        }

        private static ParsingResult[] ValidateAddresses(ValidateRequest validateRequest)
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

            var dmarcUris = validateRequest.Value.Split(',');

            foreach (var dmarcUri in dmarcUris)
            {
                if (!DmarcEmailDetail.TryParse(dmarcUri.Trim(), out var dmarcEmailDetail))
                {
                    if (DmarcEmailDetail.IsUnsupportedUri(dmarcUri.Trim()))
                    {
                        // Every URI is allowed, mail receivers only have to support "mailto:" (RFC 9989 section 4.7)
                        parsingResults.Add(new ParsingResult
                        {
                            Status = ParsingStatus.Warning,
                            Field = validateRequest.Field,
                            Message = $"Only mailto URIs are supported by mail receivers, {dmarcUri.Trim()} is ignored"
                        });

                        continue;
                    }

                    parsingResults.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Wrong dmarc uri {dmarcUri}"
                    });

                    continue;
                }

                if (dmarcEmailDetail == null)
                {
                    continue;
                }

                if (!dmarcEmailDetail.IsValidEmailAddress)
                {
                    parsingResults.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Wrong email address {dmarcEmailDetail.EmailAddress}"
                    });
                }
            }

            return [.. parsingResults];
        }
    }
}
