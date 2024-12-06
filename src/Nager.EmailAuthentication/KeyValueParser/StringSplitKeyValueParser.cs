namespace Nager.EmailAuthentication.KeyValueParser
{
    /// <summary>
    /// String Split Key Value Parser
    /// </summary>
    public class StringSplitKeyValueParser : IKeyValueParser
    {
        private readonly char _delimiter;
        private readonly char _keyValueSeparator;

        /// <summary>
        /// Initializes a new instance of the <see cref="StringSplitKeyValueParser"/> class.
        /// </summary>
        /// <param name="delimiter">The character that separates key-value pairs (default: ';').</param>
        /// <param name="keyValueSeparator">The character that separates keys from values (default: '=').</param>
        public StringSplitKeyValueParser(
            char delimiter = ';',
            char keyValueSeparator = '=')
        {
            this._delimiter = delimiter;
            this._keyValueSeparator = keyValueSeparator;
        }

        /// <inheritdoc />
        public ParseResult Parse(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                throw new ArgumentException("Input cannot be null or empty", nameof(input));
            }

            var keyValues = new List<IndexedKeyValueItem>();
            var unrecognizedParts = new List<string>();
            var index = 0;

            var parts = input.Split(this._delimiter, StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts)
            {
                var cleanPart = part.AsSpan().TrimStart(' ');
                var keyValueSeparatorIndex = cleanPart.IndexOf(this._keyValueSeparator);

                if (keyValueSeparatorIndex <= 0)
                {
                    unrecognizedParts.Add(cleanPart.ToString());
                    index++;
                    continue;
                }

                var key = cleanPart[..(keyValueSeparatorIndex)];
                var value = cleanPart[(keyValueSeparatorIndex + 1)..];

                keyValues.Add(new IndexedKeyValueItem
                {
                    Index = index,
                    Key = key.ToString(),
                    Value = value.ToString()
                });

                index++;
            }

            var parseResult = new ParseResult
            {
                KeyValues = [.. keyValues]
            };

            if (unrecognizedParts.Count > 0)
            {
                parseResult.UnrecognizedParts = [.. unrecognizedParts];
            }

            return parseResult;
        }
    }
}
