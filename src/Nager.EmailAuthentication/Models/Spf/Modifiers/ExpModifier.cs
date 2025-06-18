namespace Nager.EmailAuthentication.Models.Spf.Modifiers
{
    /// <summary>
    /// Represents the "exp" modifier in an SPF record, which provides an explanation in case of SPF failure.
    /// </summary>
    public class ExpModifier : ModifierBase
    {
        /// <summary>
        /// The key representing the "exp" modifier in an SPF record.
        /// </summary>
        public const string ModifierKey = "exp";

        /// <summary>
        /// Initializes a new instance of the <see cref="ExpModifier"/> class.
        /// </summary>
        public ExpModifier() : base(ModifierType.Exp)
        {

        }
    }
}
