FROM mcr.microsoft.com/dotnet/aspnet:8.0-nanoserver-ltsc2022
WORKDIR C:\\app
COPY publish/ .
~>USER ContainerAdministrator
ENTRYPOINT ["dotnet", "Api.dll"]
