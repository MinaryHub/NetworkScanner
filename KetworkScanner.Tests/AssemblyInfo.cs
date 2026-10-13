using Xunit;

// 여러 테스트가 UserDataPaths.OverrideRoot 같은 정적 상태를 바꾸므로 클래스 간 병렬 실행을 끈다.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
