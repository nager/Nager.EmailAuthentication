namespace Nager.EmailAuthentication.Models.Spf.Modifiers
{
    public abstract class SpfModifierBase : SpfTerm
    {
        protected char Delimiter = '=';

        public ModifierType ModifierType { get; init; }
        public string? ModifierData { get; private set; }

        public SpfModifierBase(ModifierType modifierType)
        {
            this.ModifierType = modifierType;
        }

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

        public override string ToString()
        {
            return $"{this.ModifierType} {this.ModifierData}";
        }
    }
}
