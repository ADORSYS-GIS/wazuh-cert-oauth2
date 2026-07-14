FROM nginx:alpine
RUN apk add --no-cache curl openssl gettext \
    && mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp \
       /var/cache/nginx/fastcgi_temp /var/cache/nginx/uwsgi_temp \
       /var/cache/nginx/scgi_temp \
    && chown -R nginx:nginx /var/cache/nginx \
    && chown -R nginx:nginx /etc/nginx \
    && chown -R nginx:nginx /var/log/nginx \
    && chown -R nginx:nginx /run \
    && touch /var/run/nginx.pid && chown nginx:nginx /var/run/nginx.pid \
    && mkdir -p /opt/sidecar && chown nginx:nginx /opt/sidecar \
    && sed -i 's/^user  nginx;/#user  nginx;/' /etc/nginx/nginx.conf

COPY nginx.conf.template entrypoint.sh fetch-crl.sh /opt/sidecar/
RUN chmod +x /opt/sidecar/entrypoint.sh /opt/sidecar/fetch-crl.sh

USER nginx

ENTRYPOINT ["/opt/sidecar/entrypoint.sh"]