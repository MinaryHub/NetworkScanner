namespace NetworkScanner.Platform
{
    // 현재 OS에 맞는 IArpResolver 를 고른다. 지원하지 않는 OS면 NullArpResolver.
    public static class ArpResolverFactory
    {
        public static IArpResolver CreateForCurrentOS()
        {
            if (OperatingSystem.IsWindows()) return new WindowsIpNetTableArpResolver();
            if (OperatingSystem.IsMacOS()) return new MacOSSysctlArpResolver();
            if (OperatingSystem.IsLinux()) return new LinuxProcArpResolver();
            return new NullArpResolver();
        }
    }
}
