namespace Nager.EmailAuthentication.Models.Spf.Modifiers
{
    public class RedirectModifier : SpfModifierBase
    {
        public const string ModifierKey = "redirect";

        public RedirectModifier() : base(ModifierType.Redirect)
        {

        }
    }
}
