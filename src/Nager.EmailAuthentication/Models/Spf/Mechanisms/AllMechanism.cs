namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    /// <summary>
    /// Represents the "all" mechanism in an SPF record, which matches all senders.
    /// Typically used as the last mechanism in an SPF policy.
    /// </summary>
    public class AllMechanism : MechanismBase
    {
        /// <summary>
        /// The key representing the "all" mechanism in an SPF record.
        /// </summary>
        public const string MechanismKey = "all";

        /// <summary>
        /// Initializes a new instance of the <see cref="AllMechanism"/> class.
        /// </summary>
        public AllMechanism() : base(MechanismType.All)
        {

        }
    }
}
