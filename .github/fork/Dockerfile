FROM node:24-bookworm-slim@sha256:873f586f3794f52281bd039bf02c048a0be08fde619338f9941bad1eb6b34530 AS frontend
WORKDIR /src
COPY package.json yarn.lock webpack.config.js postcss.config.js tailwind.config.js ./
RUN yarn install --frozen-lockfile --non-interactive
COPY server/assets server/assets
COPY server/templates server/templates
RUN yarn run build:production

FROM golang:1.27-bookworm@sha256:ce59b41415e2524ae99926fe1f37ce48ba8c194dcbd2a56a65436cdcefa2bd34 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-mod=vendor GOTOOLCHAIN=local
COPY go.mod go.sum main.go ./
COPY vendor vendor
COPY cmd cmd
COPY policy policy
COPY pull pull
COPY server server
COPY version version
ARG VERSION=unspecified
RUN go build -trimpath -ldflags "-s -w -X github.com/palantir/policy-bot/version.version=${VERSION}" -o /out/policy-bot .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY docker/mime.types /etc/mime.types
COPY config/policy-bot.example.yml /secrets/policy-bot.yml
WORKDIR /app
COPY server/templates templates
COPY --from=frontend /src/build/static static
COPY --from=build /out/policy-bot /usr/local/bin/policy-bot
ENTRYPOINT ["/usr/local/bin/policy-bot"]
CMD ["server", "--config", "/secrets/policy-bot.yml"]
