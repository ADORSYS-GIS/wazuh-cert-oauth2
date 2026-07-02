FROM nginx:alpine
RUN apk add --no-cache curl openssl \
    && mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp \
       /var/cache/nginx/fastcgi_temp /var/cache/nginx/uwsgi_temp \
       /var/cache/nginx/scgi_temp \
    && chown -R nginx:nginx /var/cache/nginx \
    && chown -R nginx:nginx /etc/nginx \
    && chown -R nginx:nginx /var/log/nginx \
    && chown -R nginx:nginx /run \
    && touch /var/run/nginx.pid && chown nginx:nginx /var/run/nginx.pid \
    && sed -i 's/^user  nginx;/#user  nginx;/' /etc/nginx/nginx.conf
USER nginx