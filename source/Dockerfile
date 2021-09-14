FROM mcr.microsoft.com/powershell:7.1.4-ubuntu-20.04-20210819

COPY setup.ps1 /setup.ps1
RUN pwsh /setup.ps1

COPY entrypoint.ps1 /entrypoint.ps1
COPY Noveris.CertCheck/ /usr/local/share/powershell/Modules/Noveris.CertCheck

ENTRYPOINT [ "pwsh", "/entrypoint.ps1" ]
