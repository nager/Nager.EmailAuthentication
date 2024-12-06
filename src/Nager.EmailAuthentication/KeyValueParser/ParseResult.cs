namespace Nager.EmailAuthentication.KeyValueParser
{
    /// <summary>
    /// Represents the result of a parsing operation, containing key-value pairs and unrecognized parts.
    /// </summary>
    public class ParseResult
    {
        /// <summary>
        /// An array of key-value pairs extracted during the parsing process.
        /// </summary>
        public IndexedKeyValueItem[] KeyValues { get; set; } = [];

        /// <summary>
        /// An array of unrecognized parts from the input that could not be parsed into key-value pairs.
        /// This property is nullable, meaning it can be null if there are no unrecognized parts.
        /// </summary>
        public string[]? UnrecognizedParts {  get; set; }
    }
}
