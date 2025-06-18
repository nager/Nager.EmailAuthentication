namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    /// <summary>
    /// Ip Mechanism Base
    /// </summary>
    public abstract class IpMechanismBase : MechanismBase
    {
        /// <summary>
        /// Ip Mechanism Base
        /// </summary>
        /// <param name="mechanismType"></param>
        public IpMechanismBase(MechanismType mechanismType) : base(mechanismType)
        {
        }
    }
}
