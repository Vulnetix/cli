from nginx:1.27-alpine as web
healthcheck --interval=30s --timeout=3s cmd wget -qO- http://127.0.0.1/healthz || exit 1

FROM web AS hardened
RUN rm -f /etc/nginx/conf.d/default.conf

# two levels below the stage that declares the HEALTHCHECK
FROM hardened
COPY nginx.conf /etc/nginx/conf.d/site.conf
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
