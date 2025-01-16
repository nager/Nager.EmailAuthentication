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
            parseErrors = null;

            var errors = new List<ParseError>();

            if (string.IsNullOrWhiteSpace(dkimHeader))
            {
                dkimHeaderDataFragment = null;
                return false;
            }

            var keyValueSeperator = '=';
            var keyValueParser = new KeyValueParser.MemoryEfficientKeyValueParser(';', keyValueSeperator);
            if (!keyValueParser.TryParse(dkimHeader, out var parseResult))
            {
                dkimHeaderDataFragment = null;
                return false;
            }

            if (parseResult == null)
            {
                dkimHeaderDataFragment = null;
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

            var dataFragment = new DkimHeaderDataFragment();

            var handlers = new Dictionary<string, MappingHandler>
            {
                {
                    "v", new MappingHandler
                    {
                        Map = value => dataFragment.Version = value
                    }
                },
                {
                    "a", new MappingHandler
                    {
                        Map = value => dataFragment.SignatureAlgorithm = value
                    }
                },
                {
                    "b", new MappingHandler
                    {
                        Map = value => dataFragment.SignatureData = value
                    }
                },
                {
                    "bh", new MappingHandler
                    {
                        Map = value => dataFragment.BodyHash = value
                    }
                },
                {
                    "c", new MappingHandler
                    {
                        Map = value => dataFragment.MessageCanonicalization = value
                    }
                },
                {
                    "d", new MappingHandler
                    {
                        Map = value => dataFragment.Domain = value
                    }
                },
                {
                    "s", new MappingHandler
                    {
                        Map = value => dataFragment.Selector = value
                    }
                },
                {
                    "t", new MappingHandler
                    {
                        Map = value => dataFragment.Timestamp = value
                    }
                },
                {
                    "x", new MappingHandler
                    {
                        Map = value => dataFragment.SignatureExpiration = value
                    }
                },
                {
                    "h", new MappingHandler
                    {
                        Map = value => dataFragment.SignedHeaderFields = value
                    }
                },
                {
                    "q", new MappingHandler
                    {
                        Map = value => dataFragment.QueryMethods = value
                    }
                },
                {
                    "i", new MappingHandler
                    {
                        Map = value => dataFragment.AgentOrUserIdentifier = value
                    }
                }
            };

            var mappingFound = false;

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

                    mappingFound = true;

                    continue;
                }

                errors.Add(new ParseError
                {
                    ErrorMessage = $"Unrecognized Part {keyValue.Key}{keyValueSeperator}{keyValue.Value}",
                    Severity = ErrorSeverity.Warning
                });
            }

            parseErrors = errors.Count == 0 ? null : [.. errors];
            dkimHeaderDataFragment = dataFragment;

            return mappingFound;
        }
    }
}
