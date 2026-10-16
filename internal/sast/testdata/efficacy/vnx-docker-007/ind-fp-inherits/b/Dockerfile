FROM nginx:1.27 AS base
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
EXPOSE 80
FROM base
COPY site /usr/share/nginx/html
CMD ["nginx", "-g", "daemon off;"]
