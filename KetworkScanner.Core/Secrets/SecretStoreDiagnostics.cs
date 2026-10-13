using System;

namespace KetworkScanner.Secrets
{
    // 저장소 구현체의 런타임 실패를 UI/로그로 전달하는 통로. 구현체는 예외 대신 이를 호출한다.
    public static class SecretStoreDiagnostics
    {
        public static Action<string>? OnError { get; set; }

        internal static void Report(string storeName, string message)
        {
            try
            {
                OnError?.Invoke("[" + storeName + "] " + message);
            }
            catch
            {
                // 진단 핸들러의 예외가 저장소 동작을 깨뜨려서는 안 된다.
            }
        }
    }
}
