# 헤드리스 CLI 컨테이너. 호스트 네트워크로 실행해야 LAN을 스캔할 수 있다.
#   docker build -f deploy/Dockerfile -t netscan .
#   docker run --rm --net=host --cap-add=NET_RAW -v netscan-data:/root/.config/NetworkScanner netscan --range 192.168.1.0/24
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish NetworkScanner.Cli/NetworkScanner.Cli.csproj -c Release -o /out

FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app
COPY --from=build /out .
# /proc/net/arp 를 읽으므로 arp 명령이 필요 없다. ICMP는 NET_RAW 캡으로 허용한다.
ENTRYPOINT ["dotnet", "netscan.dll"]
