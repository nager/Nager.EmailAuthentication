namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Parsing Result
    /// </summary>
    public class ParsingResult
    {
        /// <summary>
        /// Description of the parsing result
        /// </summary>
        public required string Message { get; set; }

        /// <summary>
        ///  Status of the parsing result
        /// </summary>
        public ParsingStatus Status { get; set; }
    }
}
