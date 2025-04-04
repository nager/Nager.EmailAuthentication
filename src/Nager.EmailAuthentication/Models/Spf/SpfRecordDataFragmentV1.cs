namespace Nager.EmailAuthentication.Models.Spf
{
    /// <summary>
    /// Spf Record Data Fragment
    /// </summary>
    public class SpfRecordDataFragmentV1 : SpfRecordDataFragmentBase
    {
        /// <summary>
        /// Spf Terms
        /// </summary>
        public SpfTerm[] SpfTerms { get; set; }
    }
}
