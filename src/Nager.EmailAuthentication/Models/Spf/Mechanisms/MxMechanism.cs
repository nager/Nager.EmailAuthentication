namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    /// <summary>
    /// Represents the "mx" mechanism in an SPF record, which authorizes the sender if their IP matches one of the domain's MX records.
    /// </summary>
    public class MxMechanism : SpfMechanismBase
    {
        /// <summary>
        /// The key representing the "mx" mechanism in an SPF record.
        /// </summary>
        public const string MechanismKey = "mx";

        /// <summary>
        /// Initializes a new instance of the <see cref="MxMechanism"/> class.
        /// </summary>
        public MxMechanism() : base(MechanismType.Mx)
        {

        }
    }
}
