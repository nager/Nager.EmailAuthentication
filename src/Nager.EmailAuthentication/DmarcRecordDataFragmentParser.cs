using Nager.EmailAuthentication.Handlers;
using Nager.EmailAuthentication.Models;
using System.Diagnostics.CodeAnalysis;

namespace Nager.EmailAuthentication
{
    /// <summary>
    /// Dmarc Record Data Fragment Parser
    /// </summary>
    public static class DmarcRecordDataFragmentParser
    {
        /// <summary>
        /// Attempts to parse a raw DMARC string into a <see cref="DmarcRecordDataFragment"/> object.
        /// </summary>
        /// <param name="dmarcRaw">The raw DMARC string to parse.</param>
        /// <param name="dmarcDataFragment">The parsed DMARC record, if successful.</param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string? dmarcRaw,
            [NotNullWhen(true)] out DmarcRecordDataFragment? dmarcDataFragment)
        {
            return TryParse(dmarcRaw, out dmarcDataFragment, out _);
        }

        /// <summary>
        /// Attempts to parse a raw DMARC string into a <see cref="DmarcRecordDataFragment"/> object.
        /// </summary>
        /// <param name="dmarcRaw">The raw DMARC string to parse.</param>
        /// <param name="dmarcDataFragment">The parsed DMARC record, if successful.</param>
        /// <param name="parsingResults">A list of errors in the DMARC string, if any.</param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string? dmarcRaw,
            [NotNullWhen(true)] out DmarcRecordDataFragment? dmarcDataFragment,
            out ParsingResult[]? parsingResults)
        {
            if (string.IsNullOrWhiteSpace(dmarcRaw))
            {
                parsingResults = null;
                dmarcDataFragment = null;

                return false;
            }

            var handlers = new Dictionary<string, MappingHandler<DmarcRecordDataFragment>>
            {
                {
                    "v", new MappingHandler<DmarcRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Version = value,
                        Validate = ValidateVersion
                    }
                },
                {
                    "p", new MappingHandler<DmarcRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.DomainPolicy = value,
                        Validate = ValidateDomainPolicy
                    }
                },
                {
                    "sp", new MappingHandler<DmarcRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.SubdomainPolicy = value,
                        Validate = ValidateDomainPolicy
                    }
                },
                {
                    "rua", new MappingHandler<DmarcRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.AggregateReportUri = value,
                        Validate = ValidateAddresses
                    }
                },
                {
                    "ruf", new MappingHandler<DmarcRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.ForensicReportUri = value,
                        Validate = ValidateAddresses
                    }
                },
                {
                    "rf", new MappingHandler<DmarcRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.ReportFormat = value,
                        Validate = ValidateReportFormat
                    }
                },
                {
                    "fo", new MappingHandler<DmarcRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.FailureReportingOptions = value,
                        Validate = ValidateFailureReportingOptions
                    }
                },
                {
                    "pct", new MappingHandler<DmarcRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.PolicyPercentage = value,
                        Validate = ValidatePolicyPercentage
                    }
                },
                {
                    "ri", new MappingHandler<DmarcRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.ReportingInterval = value,
                        Validate = ValidateReportingInterval
                    }
                },
                {
                    "adkim", new MappingHandler<DmarcRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.DkimAlignmentMode = value,
                        Validate = ValidateAlignmentMode
                    }
                },
                {
                    "aspf", new MappingHandler<DmarcRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.SpfAlignmentMode = value,
                        Validate = ValidateAlignmentMode
                    }
                }
            };

            var parserBase = new KeyValueParserBase<DmarcRecordDataFragment>(handlers);
            return parserBase.TryParse(dmarcRaw, out dmarcDataFragment, out parsingResults);
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

            if (!validateRequest.Value.Equals("DMARC1", StringComparison.OrdinalIgnoreCase))
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

        private static ParsingResult[] ValidatePolicyPercentage(ValidateRequest validateRequest)
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

            if (!int.TryParse(validateRequest.Value, out var percentage))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Value is not a number"
                });

                return [.. parsingResults];
            }

            if (percentage < 0 || percentage > 100)
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Value is not in allowed range"
                });

                return [.. parsingResults];
            }

            return [];
        }

        private static ParsingResult[] ValidateReportFormat(ValidateRequest validateRequest)
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

            if (!validateRequest.Value.Equals("afrf", StringComparison.OrdinalIgnoreCase))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Only allow Authentication Failure Reporting Format (afrf)"
                });

                return [.. parsingResults];
            }

            parsingResults.Add(new ParsingResult
            {
                Status = ParsingStatus.Info,
                Field = validateRequest.Field,
                Message = "Is not required"
            });

            return [.. parsingResults];
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

        private static ParsingResult[] ValidateReportingInterval(ValidateRequest validateRequest)
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

            if (!int.TryParse(validateRequest.Value, out var reportInterval))
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Value is not a number"
                });

                return [.. parsingResults];
            }

            var reportIntervalTimeSpan = TimeSpan.FromSeconds(reportInterval);

            // Time interval is less than one hour
            if (reportInterval < 3600)
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Warning,
                    Field = validateRequest.Field,
                    Message = $"Value is to small, {reportIntervalTimeSpan.TotalHours} hours"
                });

                return [.. parsingResults];
            }

            // Time interval is greater than 2 days
            if (reportInterval > 86400 * 2)
            {
                parsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Warning,
                    Field = validateRequest.Field,
                    Message = $"Value is to large, {reportIntervalTimeSpan.TotalDays} days"
                });

                return [.. parsingResults];
            }

            return [];
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
