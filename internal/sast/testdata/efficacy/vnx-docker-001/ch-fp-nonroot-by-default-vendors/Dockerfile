FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0-jammy-chiseled
COPY --from=build /app /app
ENTRYPOINT ["dotnet", "/app/Api.dll"]
