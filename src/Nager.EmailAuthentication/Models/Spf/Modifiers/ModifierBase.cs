namespace Nager.EmailAuthentication.Models.Spf.Modifiers
{
    /// <summary>
    /// Modifier Base
    /// </summary>
    public abstract class ModifierBase : SpfTerm
    {
        internal char Delimiter = '=';

        /// <summary>
        /// Modifier Type
        /// </summary>
        public ModifierType ModifierType { get; init; }

        /// <summary>
        /// Modifier Data
        /// </summary>
        public string? ModifierData { get; private set; }

        /// <summary>
        /// Modifier Base
        /// </summary>
        /// <param name="modifierType"></param>
        public ModifierBase(ModifierType modifierType)
        {
            this.ModifierType = modifierType;
        }

        /// <summary>
        /// Extracts the data part from the given SPF term.
        /// </summary>
        /// <param name="spfTerm">The SPF term from which the data part will be extracted.</param>
        public void GetDataPart(ReadOnlySpan<char> spfTerm)
        {
            var indexOfEqualSign = spfTerm.IndexOf(Delimiter);
            if (indexOfEqualSign == -1)
            {
                return;
            }

            var data = spfTerm[1..];

            this.ModifierData = data.ToString();
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            return $"{this.ModifierType} {this.ModifierData}";
        }
    }
}
