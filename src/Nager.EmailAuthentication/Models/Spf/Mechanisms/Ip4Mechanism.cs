namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    public class Ip4Mechanism : SpfMechanismBase
    {
        public const string MechanismKey = "ip4";

        public Ip4Mechanism() : base(MechanismType.Ip4)
        {

        }
    }
}
