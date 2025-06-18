namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    /// <summary>
    /// Mechanism Base
    /// </summary>
    public abstract class MechanismBase : SpfTerm
    {
        internal char Delimiter = ':';

        /// <summary>
        /// Mechanism Type
        /// </summary>
        public MechanismType MechanismType { get; init; }

        /// <summary>
        /// Qualifier
        /// </summary>
        public SpfQualifier Qualifier { get; private set; }

        /// <summary>
        /// Mechanism Data
        /// </summary>
        public string? MechanismData { get; private set; }

        /// <summary>
        /// Mechanism Base
        /// </summary>
        /// <param name="mechanismType"></param>
        public MechanismBase(MechanismType mechanismType)
        {
            this.MechanismType = mechanismType;
        }

        /// <summary>
        /// Set Qualifier
        /// </summary>
        /// <param name="qualifier"></param>
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

        /// <summary>
        /// Extracts the data part from the given SPF term.
        /// </summary>
        /// <param name="spfTerm">The SPF term from which the data part will be extracted.</param>
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

        /// <inheritdoc/>
        public override string ToString()
        {
            return $"{this.Qualifier} {this.MechanismType} {this.MechanismData}";
        }
    }
}
