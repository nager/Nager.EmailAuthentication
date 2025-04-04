namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    /// <summary>
    /// Represents the "include" mechanism in an SPF record, which includes another domain's SPF policy.
    /// </summary>
    public class IncludeMechanism : SpfMechanismBase
    {
        /// <summary>
        /// The key representing the "include" mechanism in an SPF record.
        /// </summary>
        public const string MechanismKey = "include";

        /// <summary>
        /// Initializes a new instance of the <see cref="IncludeMechanism"/> class.
        /// </summary>
        public IncludeMechanism() : base(MechanismType.Include)
        {

        }
    }
}
