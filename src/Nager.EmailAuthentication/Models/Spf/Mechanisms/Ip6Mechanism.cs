namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    public class Ip6Mechanism : SpfMechanismBase
    {
        public const string MechanismKey = "ip6";

        public Ip6Mechanism() : base(MechanismType.Ip6)
        {

        }
    }
}
