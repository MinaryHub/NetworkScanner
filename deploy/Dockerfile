# 헤드리스 CLI 컨테이너. 호스트 네트워크로 실행해야 LAN을 스캔할 수 있다.
#   docker build -f deploy/Dockerfile --build-arg VERSION=2.1.0 -t netscan .
#   docker run --rm --net=host --cap-add=NET_RAW -v netscan-data:/home/netscan/.config/KetworkScanner netscan --range 192.168.1.0/24
# 비루트 사용자(netscan)로 실행한다. ICMP는 --cap-add=NET_RAW 로 허용하고, TTL 측정은 iputils-ping의 ping(파일 capability 보유)을 쓴다.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG VERSION=2.1.0
WORKDIR /src
COPY . .
RUN dotnet publish KetworkScanner.Cli/KetworkScanner.Cli.csproj -c Release -p:Version=${VERSION} -o /out

FROM mcr.microsoft.com/dotnet/runtime:10.0
ARG VERSION=2.1.0
LABEL org.opencontainers.image.title="netscan" \
      org.opencontainers.image.description="KetworkScanner command-line scanner" \
      org.opencontainers.image.version="${VERSION}"
# iputils-ping: Linux에서는 Ping 응답의 TTL을 .NET이 주지 않아 ping 유틸리티 출력에서 읽는다(OS 추정에 사용).
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1001 netscan \
    && useradd --system --uid 1001 --gid netscan --create-home --home-dir /home/netscan --shell /usr/sbin/nologin netscan \
    && mkdir -p /home/netscan/.config/KetworkScanner \
    && chown -R netscan:netscan /home/netscan
WORKDIR /app
COPY --from=build /out .
USER netscan
ENV HOME=/home/netscan DOTNET_gcServer=0
# /proc/net/arp 를 읽으므로 arp 명령이 필요 없다.
ENTRYPOINT ["dotnet", "netscan.dll"]
