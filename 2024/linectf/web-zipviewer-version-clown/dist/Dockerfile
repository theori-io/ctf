# Build image
FROM swift:5.9-jammy as build

RUN export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true \
    && apt-get -q update \
    && apt-get -q dist-upgrade -y \
    && apt-get install -y libjemalloc-dev

WORKDIR /build

COPY ./Package.* ./
RUN swift package resolve --skip-update \
        $([ -f ./Package.resolved ] && echo "--force-resolved-versions" || true)

COPY . .

RUN swift build -c release \
                --static-swift-stdlib \
                -Xlinker -ljemalloc

WORKDIR /staging

RUN cp "$(swift build --package-path /build -c release --show-bin-path)/App" ./

RUN cp "/usr/libexec/swift/linux/swift-backtrace-static" ./

RUN find -L "$(swift build --package-path /build -c release --show-bin-path)/" -regex '.*\.resources$' -exec cp -Ra {} ./ \;

RUN [ -d /build/Public ] && { mv /build/Public ./Public && chmod -R a-w ./Public; } || true
RUN [ -d /build/Resources ] && { mv /build/Resources ./Resources && chmod -R a-w ./Resources; } || true


# Run image
FROM ubuntu:jammy

RUN export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true \
    && apt-get -q update \
    && apt-get -q dist-upgrade -y \
    && apt-get -q install -y \
      libjemalloc2 \
      ca-certificates \
      tzdata \
      tree \
      vim \
      net-tools \
      curl \
      wget \
      nginx \
    && rm -r /var/lib/apt/lists/*

RUN useradd --user-group --create-home --system --skel /dev/null --home-dir /app vapor
WORKDIR /app

# SALT
ENV SALT=THIS_IS_NOT_REAL

COPY --chown=root:root --chmod=644 ./flag /flag
RUN mkdir -p /app/Upload
RUN chmod 1777 /app/Upload

COPY ./nginx.conf /etc/nginx/nginx.conf
RUN touch /var/log/nginx/access.log
RUN touch /var/log/nginx/error.log
RUN chmod 702 /var/log/nginx/access.log
RUN chmod 702 /var/log/nginx/error.log

RUN chown -R vapor:vapor /var/lib/nginx
COPY --from=build --chown=vapor:vapor /staging /app

ENV SWIFT_BACKTRACE=enable=yes,sanitize=yes,threads=all,images=all,interactive=no,swift-backtrace=./swift-backtrace-static

USER vapor:vapor
EXPOSE 80

CMD nohup ./App serve --env production --hostname 0.0.0.0 --port 8080 & nginx -g "daemon off;"