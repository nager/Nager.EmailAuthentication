namespace Nager.EmailAuthentication.Models.Spf
{
    /// <summary>
    /// Represents a base class for all SPF terms, including mechanisms and modifiers.
    /// </summary>
    public abstract class SpfTerm
    {
        /// <summary>
        /// Gets or sets the index of the term in the SPF record.
        /// </summary>
        public int Index { get; set; }
    }
}
