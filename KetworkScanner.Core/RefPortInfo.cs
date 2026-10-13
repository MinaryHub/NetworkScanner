namespace KetworkScanner
{
    public class RefPortInfo
    {
        public int PortNo { get; set; }
        public string? Portname { get; set; }
        public string? Protocol { get; set; }

        public override string ToString()
        {
            return string.Format("{0}:{1}:{2}", PortNo, Portname, Protocol);
        }
    }
}
