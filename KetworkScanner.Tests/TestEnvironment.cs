using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace KetworkScanner.Tests
{
    // 테스트 전체가 실제 사용자 프로필 폴더(설정·이력·로그)를 건드리지 않도록 시작 시 UserDataPaths를 임시 폴더로 돌린다.
    // 자기 폴더를 쓰는 테스트는 Dispose에서 null 대신 TestEnvironment.Root로 되돌린다.
    internal static class TestEnvironment
    {
        public static string Root { get; } = Path.Combine(Path.GetTempPath(), "ketwork-tests-" + Environment.ProcessId);

        [ModuleInitializer]
        internal static void Init()
        {
            Directory.CreateDirectory(Root);
            UserDataPaths.OverrideRoot = Root;
            AppDomain.CurrentDomain.ProcessExit += (_, _) => { try { Directory.Delete(Root, recursive: true); } catch { } };
        }
    }
}
