FROM nginx:alpine
RUN apk add --no-cache curl openssl \
    && mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp \
       /var/cache/nginx/fastcgi_temp /var/cache/nginx/uwsgi_temp \
       /var/cache/nginx/scgi_temp \
    && chown -R nginx:nginx /var/cache/nginx /etc/nginx/conf.d \
    && chown nginx:nginx /run \
    && sed -i 's/^user  nginx;/#user  nginx;/' /etc/nginx/nginx.conf
USER nginx