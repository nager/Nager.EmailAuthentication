using Nager.EmailAuthentication.Models;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Nager.EmailAuthentication
{
    /// <summary>
    /// Dmarc Record Parser
    /// </summary>
    public static class DmarcRecordParser
    {
        private static readonly string[] AllowedPolicies = ["none", "quarantine", "reject"];

        /// <summary>
        /// Attempts to parse a raw DMARC string into a <see cref="DmarcDataFragment"/> object.
        /// </summary>
        /// <param name="dmarcRaw">The raw DMARC string to parse.</param>
        /// <param name="dmarcDataFragment">The parsed DMARC record, if successful.</param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string dmarcRaw,
            out DmarcDataFragment? dmarcDataFragment)
        {
            return TryParse(dmarcRaw, out dmarcDataFragment, out _);
        }

        /// <summary>
        /// Attempts to parse a raw DMARC string into a <see cref="DmarcDataFragment"/> object.
        /// </summary>
        /// <param name="dmarcRaw">The raw DMARC string to parse.</param>
        /// <param name="dmarcDataFragment">The parsed DMARC record, if successful.</param>
        /// <param name="parseErrors">A list of errors in the DMARC string, if any.</param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string dmarcRaw,
            out DmarcDataFragment? dmarcDataFragment,
            out ParseError[]? parseErrors)
        {
            parseErrors = null;

            var errors = new List<ParseError>();

            if (string.IsNullOrWhiteSpace(dmarcRaw))
            {
                dmarcDataFragment = null;
                return false;
            }

            if (!dmarcRaw.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Critical,
                    ErrorMessage = "DMARC record is invalid: it must start with 'v=DMARC1'."
                });
            }

            var keyValueSeperator = '=';
            var keyValueParser = new KeyValueParser.MemoryEfficientKeyValueParser(';', keyValueSeperator);
            if (!keyValueParser.TryParse(dmarcRaw, out var parseResult))
            {
                dmarcDataFragment = null;
                return false;
            }

            if (parseResult == null)
            {
                dmarcDataFragment = null;
                return false;
            }

            var duplicateConfigurations = parseResult.KeyValues
                .GroupBy(o => o.Key)
                .Where(g => g.Count() > 1);

            foreach (var duplicate in duplicateConfigurations)
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Error,
                    ErrorMessage = $"Duplicate configuration detected for key: '{duplicate.Key}'."
                });
            }

            var dataFragment = new DmarcDataFragment();

            var handlers = new Dictionary<string, MappingHandler>
            {
                {
                    "v", new MappingHandler
                    {
                        Map = value => dataFragment.Version = value
                    }
                },
                {
                    "p", new MappingHandler
                    {
                        Map = value => dataFragment.DomainPolicy = value,
                        Validate = ValidateDomainPolicy
                    }
                },
                {
                    "sp", new MappingHandler
                    {
                        Map = value => dataFragment.SubdomainPolicy = value,
                        Validate = ValidateDomainPolicy
                    }
                },
                {
                    "rua", new MappingHandler
                    {
                        Map = value => dataFragment.AggregateReportUri = value
                    }
                },
                {
                    "ruf", new MappingHandler
                    {
                        Map = value => dataFragment.ForensicReportUri = value
                    }
                },
                {
                    "rf", new MappingHandler
                    {
                        Map = value => dataFragment.ReportFormat = value,
                        Validate = ValidateReportFormat
                    }
                },
                {
                    "fo", new MappingHandler
                    {
                        Map = value => dataFragment.FailureOptions = value
                    }
                },
                {
                    "pct", new MappingHandler
                    {
                        Map = value => dataFragment.PolicyPercentage = value,
                        Validate = ValidatePolicyPercentage
                    }
                },
                {
                    "ri", new MappingHandler
                    {
                        Map = value => dataFragment.ReportingInterval = value
                    }
                },
                {
                    "adkim", new MappingHandler
                    {
                        Map = value => dataFragment.DkimAlignmentMode = value
                    }
                },
                {
                    "aspf", new MappingHandler
                    {
                        Map = value => dataFragment.SpfAlignmentMode = value
                    }
                }
            };

            foreach (var keyValue in parseResult.KeyValues)
            {
                if (string.IsNullOrEmpty(keyValue.Key))
                {
                    continue;
                }

                if (handlers.TryGetValue(keyValue.Key.ToLowerInvariant(), out var handler))
                {
                    if (handler.Validate != null)
                    {
                        errors.AddRange([.. handler.Validate(new ValidateRequest { Field = keyValue.Key, Value = keyValue.Value })]);
                    }
                    handler.Map(keyValue.Value ?? "");
                    
                    continue;
                }

                errors.Add(new ParseError
                {
                    ErrorMessage = $"Unrecognized Part {keyValue.Key}{keyValueSeperator}{keyValue.Value}",
                    Severity = ErrorSeverity.Warning
                });
            }

            parseErrors = errors.Count == 0 ? null : [.. errors];
            dmarcDataFragment = dataFragment;

            return true;
        }

        private static ParseError[] ValidateDomainPolicy(ValidateRequest validateRequest)
        {
            if (string.IsNullOrEmpty(validateRequest.Value))
            {
                return [];
            }

            var errors = new List<ParseError>();

            var domainPolicy = AllowedPolicies
                .Where(policy => policy.Equals(validateRequest.Value, StringComparison.OrdinalIgnoreCase))
                .SingleOrDefault();

            if (domainPolicy == null)
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Error,
                    ErrorMessage = $"Unknown policy \"{validateRequest.Value}\""
                });
            }

            return [.. errors];
        }

        private static ParseError[] ValidatePolicyPercentage(ValidateRequest validateRequest)
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

            if (!int.TryParse(validateRequest.Value, out var percentage))
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Error,
                    ErrorMessage = $"{validateRequest.Field} value is not a number"
                });

                return [.. errors];
            }

            if (percentage < 0 || percentage > 100)
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Error,
                    ErrorMessage = $"{validateRequest.Field} value is not in allowed range"
                });

                return [.. errors];
            }

            return [];
        }

        private static ParseError[] ValidateReportFormat(ValidateRequest validateRequest)
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

            if (!validateRequest.Value.Equals("afrf", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add(new ParseError
                {
                    Severity = ErrorSeverity.Error,
                    ErrorMessage = $"{validateRequest.Field} only allow Authentication Failure Reporting Format (afrf)"
                });

                return [.. errors];
            }

            return [];
        }
    }
}
