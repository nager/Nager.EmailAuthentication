namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    public abstract class SpfMechanismBase : SpfTerm
    {
        protected char Delimiter = ':';
        
        public MechanismType MechanismType { get; init; }
        public SpfQualifier Qualifier { get; private set; }
        public string? MechanismData { get; private set; }

        public SpfMechanismBase(MechanismType mechanismType)
        {
            this.MechanismType = mechanismType;
        }

        public void SetQualifier(char qualifier)
        {
            switch (qualifier)
            {
                case '+':
                    this.Qualifier = SpfQualifier.Pass;
                    return;
                case '~':
                    this.Qualifier = SpfQualifier.SoftFail;
                    return;
                case '-':
                    this.Qualifier = SpfQualifier.Fail;
                    return;
                case '?':
                    this.Qualifier = SpfQualifier.SoftFail;
                    return;
                default:
                    this.Qualifier = SpfQualifier.Unknown;
                    break;
            }
        }

        public void GetDataPart(ReadOnlySpan<char> spfTerm)
        {
            var indexOfColonSign = spfTerm.IndexOf(Delimiter);
            if (indexOfColonSign == -1)
            {
                return;
            }

            var data = spfTerm[1..];

            this.MechanismData = data.ToString();
        }

        public override string ToString()
        {
            return $"{this.Qualifier} {this.MechanismType} {this.MechanismData}";
        }
    }
}
