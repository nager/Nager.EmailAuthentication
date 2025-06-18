namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    /// <summary>
    /// Represents the "ip6" mechanism in an SPF record, which authorizes the sender if their IP matches a specified IPv6 address or range.
    /// </summary>
    public class Ip6Mechanism : IpMechanismBase
    {
        /// <summary>
        /// The key representing the "ip6" mechanism in an SPF record.
        /// </summary>
        public const string MechanismKey = "ip6";

        /// <summary>
        /// Initializes a new instance of the <see cref="Ip6Mechanism"/> class.
        /// </summary>
        public Ip6Mechanism() : base(MechanismType.Ip6)
        {

        }
    }
}
