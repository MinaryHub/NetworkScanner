using System.Runtime.CompilerServices;

// Platform 폴더의 internal 파싱 메서드를 xUnit 테스트에서 직접 검증할 수 있도록 공개한다.
[assembly: InternalsVisibleTo("KetworkScanner.Tests")]
