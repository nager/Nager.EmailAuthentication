﻿using Nager.EmailAuthentication.Handlers;
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
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Critical,
                    Field = validateRequest.Field,
                    Message = "DMARC record is invalid: it must start with 'v=DMARC1'."
                });
                
                return [.. errors];
            }

            if (!validateRequest.Value.Equals("DMARC1", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Critical,
                    Field = validateRequest.Field,
                    Message = "DMARC record is invalid: it must start with 'v=DMARC1'."
                });
            }

            return [.. errors];
        }

        private static ParsingResult[] ValidateDomainPolicy(ValidateRequest validateRequest)
        {
            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                return [];
            }

            var errors = new List<ParsingResult>();
            var allowedPolicies = Enum.GetNames<DmarcPolicy>();

            var domainPolicy = allowedPolicies
                .Where(policy => policy.Equals(validateRequest.Value, StringComparison.OrdinalIgnoreCase))
                .SingleOrDefault();

            if (domainPolicy == null)
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = $"Unknown policy \"{validateRequest.Value}\""
                });
            }

            return [.. errors];
        }

        private static ParsingResult[] ValidatePolicyPercentage(ValidateRequest validateRequest)
        {
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Is empty"
                });

                return [.. errors];
            }

            if (!int.TryParse(validateRequest.Value, out var percentage))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Value is not a number"
                });

                return [.. errors];
            }

            if (percentage < 0 || percentage > 100)
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Value is not in allowed range"
                });

                return [.. errors];
            }

            return [];
        }

        private static ParsingResult[] ValidateReportFormat(ValidateRequest validateRequest)
        {
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Is empty"
                });

                return [.. errors];
            }

            if (!validateRequest.Value.Equals("afrf", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Only allow Authentication Failure Reporting Format (afrf)"
                });

                return [.. errors];
            }

            errors.Add(new ParsingResult
            {
                Status = ParsingStatus.Info,
                Field = validateRequest.Field,
                Message = "Is not required"
            });

            return [.. errors];
        }

        private static ParsingResult[] ValidateFailureReportingOptions(ValidateRequest validateRequest)
        {
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Is empty"
                });

                return [.. errors];
            }

            errors.Add(new ParsingResult
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
                    errors.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Wrong config {validateRequest.Value}"
                    });
                }

                return [.. errors];
            }

            if (!validateRequest.Value.Contains(':'))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "No colon found"
                });

                return [.. errors];
            }

            var parts = validateRequest.Value.Split(':');
            foreach (var part in parts)
            {
                if (part.Length != 1)
                {
                    errors.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Option invalid {part}"
                    });

                    continue;
                }

                if (!allowedOptions.Contains(part[0]))
                {
                    errors.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Wrong config {part[0]}"
                    });
                }
            }

            return [.. errors];
        }

        private static ParsingResult[] ValidateReportingInterval(ValidateRequest validateRequest)
        {
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Is empty"
                });

                return [.. errors];
            }

            if (!int.TryParse(validateRequest.Value, out var reportInterval))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Value is not a number"
                });

                return [.. errors];
            }

            var reportIntervalTimeSpan = TimeSpan.FromSeconds(reportInterval);

            // Time interval is less than one hour
            if (reportInterval < 3600)
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Warning,
                    Field = validateRequest.Field,
                    Message = $"Value is to small, {reportIntervalTimeSpan.TotalHours} hours"
                });

                return [.. errors];
            }

            // Time interval is greater than 2 days
            if (reportInterval > 86400 * 2)
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Warning,
                    Field = validateRequest.Field,
                    Message = $"Value is to large, {reportIntervalTimeSpan.TotalDays} days"
                });

                return [.. errors];
            }

            return [];
        }

        private static ParsingResult[] ValidateAlignmentMode(ValidateRequest validateRequest)
        {
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Is empty"
                });

                return [.. errors];
            }

            var allowedOptions = new char[] { 'r', 's' };

            if (validateRequest.Value.Length == 1)
            {
                if (!allowedOptions.Contains(validateRequest.Value[0]))
                {
                    errors.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Wrong config {validateRequest.Value}"
                    });
                }

                return [.. errors];
            }

            errors.Add(new ParsingResult
            {
                Status = ParsingStatus.Error,
                Field = validateRequest.Field,
                Message = $"Wrong config {validateRequest.Value}"
            });

            return [.. errors];
        }

        private static ParsingResult[] ValidateAddresses(ValidateRequest validateRequest)
        {
            var errors = new List<ParsingResult>();

            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                errors.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Field = validateRequest.Field,
                    Message = "Is empty"
                });

                return [.. errors];
            }

            var dmarcUris = validateRequest.Value.Split(',');

            foreach (var dmarcUri in dmarcUris)
            {
                if (!DmarcEmailDetail.TryParse(dmarcUri.Trim(), out var dmarcEmailDetail))
                {
                    errors.Add(new ParsingResult
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
                    errors.Add(new ParsingResult
                    {
                        Status = ParsingStatus.Error,
                        Field = validateRequest.Field,
                        Message = $"Wrong email address {dmarcEmailDetail.EmailAddress}"
                    });
                }
            }

            return [.. errors];
        }
    }
}
