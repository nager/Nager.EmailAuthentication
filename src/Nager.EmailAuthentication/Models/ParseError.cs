namespace Nager.EmailAuthentication.Models
{
    /// <summary>
    /// Parse Error
    /// </summary>
    public class ParseError
    {
        /// <summary>
        /// Description of the error
        /// </summary>
        public required string ErrorMessage { get; set; }

        /// <summary>
        ///  Severity of the error
        /// </summary>
        public ErrorSeverity Severity { get; set; }
    }
}
