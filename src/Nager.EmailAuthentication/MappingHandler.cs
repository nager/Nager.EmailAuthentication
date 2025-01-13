using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication
{
    /// <summary>
    /// Represents a handler for mapping and validating input data.
    /// </summary>
    internal class MappingHandler
    {
        /// <summary>
        /// Gets or sets the action used to map a string input.
        /// This action is required and defines how the input is processed or transformed.
        /// </summary>
        public required Action<string> Map { get; set; }

        /// <summary>
        /// Gets or sets the optional validation logic for the input string.
        /// Returns an array of <see cref="ParseError"/> objects indicating validation issues, or null if validation is not performed.
        /// </summary>
        public Func<ValidateRequest, ParseError[]>? Validate { get; set; }
    }
}
