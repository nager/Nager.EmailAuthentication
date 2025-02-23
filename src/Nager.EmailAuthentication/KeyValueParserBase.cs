using Nager.EmailAuthentication.Handlers;
using Nager.EmailAuthentication.Models;
using Nager.KeyValueParser;

namespace Nager.EmailAuthentication
{
    /// <summary>
    /// Base class for parsing key-value pairs into a strongly-typed object of type <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T">The type of the target object for parsed data. Must be a reference type with a parameterless constructor.</typeparam>
    internal class KeyValueParserBase<T> where T : class, new()
    {
        private readonly Dictionary<string, MappingHandler<T>> _mappingHandlers;
        private readonly IKeyValueParser _keyValueParser;
        private readonly char _keyValueSeparator;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyValueParserBase{T}"/> class.
        /// </summary>
        /// <param name="mappingHandlers">A dictionary of handlers to map and validate key-value pairs to properties of <typeparamref name="T"/>.</param>
        public KeyValueParserBase(
            Dictionary<string, MappingHandler<T>> mappingHandlers)
        {
            this._mappingHandlers = mappingHandlers;

            var tagDelimiter = ';';
            this._keyValueSeparator = '=';
            this._keyValueParser = new MemoryEfficientKeyValueParser(tagDelimiter, this._keyValueSeparator);
        }

        /// <summary>
        /// Attempts to parse raw key-value data into an object of type <typeparamref name="T"/>.
        /// </summary>
        /// <param name="rawData">The raw input string containing key-value pairs.</param>
        /// <param name="dataFragment">The parsed object of type <typeparamref name="T"/> if parsing is successful; otherwise, null.</param>
        /// <param name="parsingResults">An array of parsing errors or warnings, if any; otherwise, null.</param>
        /// <returns>True if at least one key-value pair is successfully mapped; otherwise, false.</returns>
        public bool TryParse(
            string rawData,
            out T? dataFragment,
            out ParsingResult[]? parsingResults)
        {
            parsingResults = null;

            if (!this._keyValueParser.TryParse(rawData, out var parseResult) || parseResult == null)
            {
                dataFragment = null;
                return false;
            }

            var tempParsingResults = new List<ParsingResult>();

            // Detect duplicate keys
            var duplicateConfigurations = parseResult.KeyValues
                .GroupBy(o => o.Key)
                .Where(g => g.Count() > 1);

            foreach (var duplicate in duplicateConfigurations)
            {
                tempParsingResults.Add(new ParsingResult
                {
                    Status = ParsingStatus.Error,
                    Message = $"Duplicate configuration detected for key: '{duplicate.Key}'."
                });
            }

            var tempDataFragment = new T();
            var mappingFound = false;

            foreach (var keyValue in parseResult.KeyValues)
            {
                if (string.IsNullOrEmpty(keyValue.Key))
                {
                    continue;
                }

                if (this._mappingHandlers.TryGetValue(keyValue.Key.ToLowerInvariant(), out var handler))
                {
                    if (handler.Validate != null)
                    {
                        var mappingErrors = handler.Validate(new ValidateRequest { Field = keyValue.Key, Value = keyValue.Value });
                        if (mappingErrors?.Length > 0)
                        {
                            tempParsingResults.AddRange(mappingErrors);
                        }
                    }

                    handler.Map(tempDataFragment, keyValue.Value ?? "");
                    mappingFound = true;
                    continue;
                }

                tempParsingResults.Add(new ParsingResult
                {
                    Field = keyValue.Key,
                    Message = $"Unrecognized part: {keyValue.Key}{this._keyValueSeparator}{keyValue.Value}",
                    Status = ParsingStatus.Warning
                });
            }

            parsingResults = tempParsingResults.Count == 0 ? null : [.. tempParsingResults];
            dataFragment = tempDataFragment;

            return mappingFound;
        }
    }
}
