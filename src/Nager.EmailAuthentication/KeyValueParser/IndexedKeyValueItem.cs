namespace Nager.EmailAuthentication.KeyValueParser
{
    /// <summary>
    /// Represents a key-value pair with an additional index.
    /// </summary>
    public record IndexedKeyValueItem
    {
        /// <summary>
        /// The index of the key-value pair in a collection.
        /// </summary>
        public int Index { get; set; }

        /// <summary>
        /// The key of the key-value pair.
        /// </summary>
        public string? Key { get; set; }

        /// <summary>
        /// The value of the key-value pair.
        /// </summary>
        public string? Value { get; set; }
    }
}
