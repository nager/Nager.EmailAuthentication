namespace Nager.EmailAuthentication.KeyValueParser
{
    /// <summary>
    /// Memory Efficient Key Value Parser
    /// </summary>
    public class MemoryEfficientKeyValueParser : IKeyValueParser
    {
        private readonly char _delimiter;
        private readonly char _keyValueSeparator;

        /// <summary>
        /// Initializes a new instance of the <see cref="MemoryEfficientKeyValueParser"/> class.
        /// </summary>
        /// <param name="delimiter">The character that separates key-value pairs (default: ';').</param>
        /// <param name="keyValueSeparator">The character that separates keys from values (default: '=').</param>
        public MemoryEfficientKeyValueParser(
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

            var inputSpan = input.AsSpan();
            var nextIndexOfDelimiter = 0;

            var keyValues = new List<IndexedKeyValueItem>();
            var unrecognizedParts = new List<string>();
            var index = 0;

            while (nextIndexOfDelimiter != -1)
            {
                nextIndexOfDelimiter = inputSpan.IndexOf(this._delimiter);

                ReadOnlySpan<char> value;
                if (nextIndexOfDelimiter == -1)
                {
                    value = inputSpan.Trim();
                }
                else
                {
                    value = inputSpan[..nextIndexOfDelimiter].Trim();
                }

                var keyValueSeparatorIndex = value.IndexOf(this._keyValueSeparator);
                var key = value[..keyValueSeparatorIndex];
                var dataStartIndex = keyValueSeparatorIndex + 1;

                if (dataStartIndex > value.Length)
                {
                    //failure...
                    break;
                }

                keyValues.Add(new IndexedKeyValueItem
                {
                    Index = index,
                    Key = key.ToString(),
                    Value = value[dataStartIndex..].ToString()
                });

                inputSpan = inputSpan[(nextIndexOfDelimiter + 1)..];
                if (inputSpan.IsEmpty)
                {
                    break;
                }

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
