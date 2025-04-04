namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    /// <summary>
    /// Represents the "ip4" mechanism in an SPF record, which authorizes the sender if their IP matches a specified IPv4 address or range.
    /// </summary>
    public class Ip4Mechanism : SpfMechanismBase
    {
        /// <summary>
        /// The key representing the "ip4" mechanism in an SPF record.
        /// </summary>
        public const string MechanismKey = "ip4";

        /// <summary>
        /// Initializes a new instance of the <see cref="Ip4Mechanism"/> class.
        /// </summary>
        public Ip4Mechanism() : base(MechanismType.Ip4)
        {

        }
    }
}
