using System.Collections.Generic;

namespace NetworkScanner.Reports
{
    // PdfReport.Build의 선택 항목.
    public sealed class PdfReportOptions
    {
        // 표 컬럼이 많아 기본은 가로(A4 landscape). false면 세로 A4에 글자를 줄여 맞춘다.
        public bool Landscape { get; set; } = true;

        // 직전 스캔 대비 변화 목록. 주어지면 표 앞에 "마지막 스캔 이후 변화" 섹션을 넣는다.
        public IReadOnlyList<ScanChange>? Changes { get; set; }

        // 제목 아래에 넣을 부제(예: 스캔 범위). null이면 생략.
        public string? Subtitle { get; set; }
    }
}
