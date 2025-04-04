namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    /// <summary>
    /// Represents the "ptr" mechanism in an SPF record, which authorizes the sender based on reverse DNS lookups.
    /// </summary>
    public class PtrMechanism : SpfMechanismBase
    {
        /// <summary>
        /// The key representing the "ptr" mechanism in an SPF record.
        /// </summary>
        public const string MechanismKey = "ptr";

        /// <summary>
        /// Initializes a new instance of the <see cref="PtrMechanism"/> class.
        /// </summary>
        public PtrMechanism() : base(MechanismType.Ptr)
        {

        }
    }
}
