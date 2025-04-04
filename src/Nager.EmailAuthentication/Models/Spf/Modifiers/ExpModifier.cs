namespace Nager.EmailAuthentication.Models.Spf.Modifiers
{
    public class ExpModifier : SpfModifierBase
    {
        public const string ModifierKey = "exp";

        public ExpModifier() : base(ModifierType.Exp)
        {

        }
    }
}
