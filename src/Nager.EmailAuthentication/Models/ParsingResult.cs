namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Parsing Result
    /// </summary>
    public class ParsingResult
    {
        /// <summary>
        /// Parsing Field
        /// </summary>
        public string? Field { get; set; }

        /// <summary>
        /// Description of the parsing result
        /// </summary>
        public required string Message { get; set; }

        /// <summary>
        ///  Status of the parsing result
        /// </summary>
        public ParsingStatus Status { get; set; }

        /// <inheritdoc/>
        public override string ToString()
        {
            return $"{Status, -10} [{Field}]: {Message}";
        }
    }
}
