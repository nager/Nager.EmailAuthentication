namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    public class IncludeMechanism : SpfMechanismBase
    {
        public const string MechanismKey = "include";

        public IncludeMechanism() : base(MechanismType.Include)
        {

        }
    }
}
