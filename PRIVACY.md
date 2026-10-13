# KetworkScanner Privacy Policy

_Last updated: 2026-10-13_

KetworkScanner (the "App") is a network inventory and security scanning tool published by **minary**. This policy explains what data the App handles and where it goes. The short version: everything the App collects stays on your computer unless you explicitly configure it to send data somewhere.

## 1. Data the App collects

When you run a scan, the App probes the IP address range **you choose** and records, for each device that answers:

- IP address, MAC address and the vendor derived from it
- host name, device model/type, operating system guess, open TCP ports and service banners
- names and descriptions announced by the device itself (mDNS/SSDP/SNMP/NetBIOS/SMB)
- the time the device was seen and any notes, owner or tags **you** type in

This information describes devices on the network you are scanning. It may indirectly identify people (for example a host name such as "Jane's iPhone"). You are responsible for scanning only networks you own or are authorised to scan.

## 2. Where the data is stored

All scan results, history, inventory, settings and reports are stored **locally** in your user profile folder (`%APPDATA%\KetworkScanner` on Windows, or the package-private folder of the Microsoft Store version). Passwords and tokens you enter for uploads or e-mail are stored in the operating-system credential store or in an encrypted file in that folder, never in plain text.

The developer has **no access** to this data. The App contains no analytics, advertising or telemetry, and never sends scan results to the developer.

## 3. Data that leaves your computer (only when you turn it on)

- **Report upload** – if you configure an FTPS/SFTP/HTTPS destination, scan reports (CSV/HTML/JSON/PDF) are sent to **that server of your choice**.
- **Notifications** – if you configure a webhook, syslog server or SMTP server, change alerts are sent to **those endpoints of your choice**.
- **Automatic updates and reference data** – the App periodically contacts GitHub (`api.github.com`, `github.com`, `raw.githubusercontent.com`) to check for a new version and for updated port lists, vendor (OUI) tables and vulnerability rules. These requests carry only the standard HTTP information (your IP address and a user-agent string) and are subject to [GitHub's privacy statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement). You can disable both checks in Settings → Updates. The Microsoft Store version receives application updates through the Store instead.

No other network traffic leaves your computer except the scan probes you start.

## 4. Permissions

The App declares the Windows capabilities `internetClient` and `privateNetworkClientServer` (to scan your local network and reach the servers you configure) and `runFullTrust` (it is a classic desktop application).

## 5. Your control

You can delete all data at any time by removing the user profile folder named above or by uninstalling the App (the Microsoft Store version removes its package-private data on uninstall). Uploaded reports and notifications live on the servers you configured and are governed by their operators.

## 6. Children

The App is a professional network administration tool and is not directed at children under 13.

## 7. Changes and contact

Changes to this policy are published at the same address as this document and noted in the App's change log. Questions: open an issue at https://github.com/MinaryHub/KetworkScanner/issues.

---

# KetworkScanner 개인정보처리방침

_최종 수정: 2026-10-13_

KetworkScanner(이하 "앱")는 **minary**가 배포하는 네트워크 인벤토리·보안 스캔 도구입니다. 이 문서는 앱이 다루는 데이터와 그 데이터가 어디로 가는지 설명합니다. 요약하면, 앱이 수집한 정보는 사용자가 직접 전송하도록 설정하지 않는 한 모두 사용자의 컴퓨터 안에만 머뭅니다.

## 1. 앱이 수집하는 데이터

스캔을 실행하면 앱은 **사용자가 지정한** IP 대역에 탐색 패킷을 보내고, 응답한 장비마다 다음을 기록합니다.

- IP 주소, MAC 주소와 그로부터 유추한 제조사
- 호스트 이름, 장비 모델·종류, 추정 운영체제, 열린 TCP 포트와 서비스 배너
- 장비가 스스로 알리는 이름과 설명(mDNS/SSDP/SNMP/NetBIOS/SMB)
- 장비를 발견한 시각, 그리고 **사용자**가 입력한 메모·담당자·태그

이 정보는 스캔 대상 네트워크의 장비를 설명하며, 간접적으로 사람을 식별할 수 있는 값(예: "홍길동의 iPhone" 같은 호스트 이름)이 포함될 수 있습니다. 본인이 소유하거나 스캔 권한이 있는 네트워크만 스캔할 책임은 사용자에게 있습니다.

## 2. 데이터 저장 위치

스캔 결과, 이력, 인벤토리, 설정, 보고서는 모두 사용자 프로필 폴더(Windows `%APPDATA%\KetworkScanner`, Microsoft Store 버전은 패키지 전용 폴더)에 **로컬로** 저장됩니다. 업로드·메일용 비밀번호와 토큰은 운영체제 자격 증명 저장소 또는 암호화된 파일에만 저장되며 평문으로 기록되지 않습니다.

개발자는 이 데이터에 **접근할 수 없습니다.** 앱에는 분석·광고·원격 측정 기능이 없으며, 스캔 결과를 개발자에게 보내지 않습니다.

## 3. 컴퓨터 밖으로 나가는 데이터 (사용자가 켠 경우에만)

- **보고서 업로드** – FTPS/SFTP/HTTPS 대상을 설정하면 스캔 보고서(CSV/HTML/JSON/PDF)가 **사용자가 지정한 서버**로 전송됩니다.
- **알림** – 웹훅, syslog 서버, SMTP 서버를 설정하면 변경 알림이 **사용자가 지정한 곳**으로 전송됩니다.
- **자동 업데이트와 참조 데이터** – 앱은 새 버전과 갱신된 포트 목록·제조사(OUI) 표·취약점 규칙을 확인하기 위해 주기적으로 GitHub(`api.github.com`, `github.com`, `raw.githubusercontent.com`)에 접속합니다. 이 요청에는 표준 HTTP 정보(IP 주소, user-agent)만 포함되며 [GitHub 개인정보 보호정책](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement)의 적용을 받습니다. 두 확인 모두 설정 → 업데이트에서 끌 수 있습니다. Microsoft Store 버전의 앱 업데이트는 Store를 통해 이루어집니다.

사용자가 시작한 스캔 탐색 외에 다른 네트워크 트래픽은 발생하지 않습니다.

## 4. 권한

앱은 Windows 기능 `internetClient`, `privateNetworkClientServer`(로컬 네트워크 스캔과 사용자가 설정한 서버 접속)와 `runFullTrust`(일반 데스크톱 앱)를 선언합니다.

## 5. 사용자의 통제

위 사용자 프로필 폴더를 삭제하거나 앱을 제거하면 모든 데이터가 삭제됩니다(Microsoft Store 버전은 제거 시 패키지 전용 데이터가 함께 삭제됩니다). 업로드한 보고서와 알림은 사용자가 설정한 서버에 남으며 해당 서버 운영자의 정책을 따릅니다.

## 6. 아동

앱은 전문 네트워크 관리 도구이며 13세 미만 아동을 대상으로 하지 않습니다.

## 7. 변경과 문의

이 방침의 변경 사항은 같은 주소에 게시하고 앱의 변경 이력에 기록합니다. 문의: https://github.com/MinaryHub/KetworkScanner/issues
