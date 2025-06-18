namespace Nager.EmailAuthentication.Models.Spf.Modifiers
{
    /// <summary>
    /// Represents the "redirect" modifier in an SPF record, which redirects SPF evaluation to another domain's policy.
    /// </summary>
    public class RedirectModifier : ModifierBase
    {
        /// <summary>
        /// The key representing the "redirect" modifier in an SPF record.
        /// </summary>
        public const string ModifierKey = "redirect";

        /// <summary>
        /// Initializes a new instance of the <see cref="RedirectModifier"/> class.
        /// </summary>
        public RedirectModifier() : base(ModifierType.Redirect)
        {

        }
    }
}
