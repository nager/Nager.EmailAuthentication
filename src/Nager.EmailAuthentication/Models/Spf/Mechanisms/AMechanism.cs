namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    /// <summary>
    /// Represents the "a" mechanism in an SPF record, which authorizes the sender if their IP matches the domain's A record.
    /// </summary>
    public class AMechanism : MechanismBase
    {
        /// <summary>
        /// The key representing the "a" mechanism in an SPF record.
        /// </summary>
        public const string MechanismKey = "a";

        /// <summary>
        /// Initializes a new instance of the <see cref="AMechanism"/> class.
        /// </summary>
        public AMechanism() : base(MechanismType.A)
        {

        }
    }
}
