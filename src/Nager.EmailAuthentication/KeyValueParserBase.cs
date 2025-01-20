using Nager.EmailAuthentication.Models;
using Nager.KeyValueParser;

namespace Nager.EmailAuthentication
{
    internal class KeyValueParserBase<T> where T : class, new()
    {
        private readonly Dictionary<string, MappingHandler<T>> _mappingHandlers;
        private readonly IKeyValueParser _keyValueParser;
        private readonly char _keyValueSeperator;

        public KeyValueParserBase(
            Dictionary<string, MappingHandler<T>> mappingHandlers)
        {
            this._mappingHandlers = mappingHandlers;

            var tagDelimiter = ';';
            this._keyValueSeperator = '=';
            this._keyValueParser = new MemoryEfficientKeyValueParser(tagDelimiter, this._keyValueSeperator);
        }

        public bool TryParse(
            string rawData,
            out T? dataFragment,
            out ParseError[]? parseErrors)
        {
            parseErrors = null;

            if (!this._keyValueParser.TryParse(rawData, out var parseResult))
            {
                dataFragment = null;
                return false;
            }

            if (parseResult == null)
            {
                dataFragment = null;
                return false;
            }

            var errors = new List<ParseError>();

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
                        if (mappingErrors != null && mappingErrors.Length > 0)
                        {
                            errors.AddRange(mappingErrors);
                        }
                    }
                    handler.Map(tempDataFragment, keyValue.Value ?? "");

                    mappingFound = true;

                    continue;
                }

                errors.Add(new ParseError
                {
                    ErrorMessage = $"Unrecognized Part {keyValue.Key}{this._keyValueSeperator}{keyValue.Value}",
                    Severity = ErrorSeverity.Warning
                });
            }

            parseErrors = errors.Count == 0 ? null : [.. errors];

            dataFragment = tempDataFragment;

            return mappingFound;
        }
    }
}
