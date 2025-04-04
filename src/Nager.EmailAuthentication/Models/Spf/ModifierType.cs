namespace Nager.EmailAuthentication.Models.Spf
{
    /// <summary>
    /// Represents the different types of modifiers used in SPF (Sender Policy Framework) records.
    /// Modifiers provide additional control and redirection capabilities within an SPF policy.
    /// </summary>
    public enum ModifierType
    {
        /// <summary>
        /// The `redirect` modifier allows delegation of SPF evaluation to another domain.
        /// Example: redirect=spf.example.com
        /// </summary>
        Redirect,

        /// <summary>
        /// The `exp` modifier specifies a domain that contains an explanation string
        /// for SPF failures, which can be included in error messages.
        /// Example: exp=explain.example.com
        /// </summary>
        Exp
    }
}
