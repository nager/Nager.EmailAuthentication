namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    public class AllMechanism : SpfMechanismBase
    {
        public const string MechanismKey = "all";

        public AllMechanism() : base(MechanismType.All)
        {

        }
    }
}
