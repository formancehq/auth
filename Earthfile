VERSION 0.8

IMPORT github.com/formancehq/earthly:tags/v0.19.1 AS core

FROM core+base-image

CACHE --sharing=shared --id go-auth-cache /go/pkg/mod
CACHE --sharing=shared --id go-auth-cache /root/.cache/go-build

sources:
    WORKDIR /src
    COPY go.* .
    COPY --dir cmd pkg .
    COPY main.go .
    SAVE ARTIFACT /src

compile:
    FROM core+builder-image
    COPY (+sources/*) /src

    CACHE --id go-auth-cache /go/pkg/mod
    CACHE --id go-auth-cache /root/.cache/go-build
    WORKDIR /src
    ARG VERSION=latest
    DO --pass-args core+GO_COMPILE --VERSION=$VERSION

build-image:
    FROM core+final-image
    ENTRYPOINT ["/bin/auth"]
    CMD ["serve"]
    COPY (+compile/main) /bin/auth
    ARG REPOSITORY=ghcr.io
    ARG tag=latest
    DO core+SAVE_IMAGE --COMPONENT=auth --REPOSITORY=${REPOSITORY} --TAG=$tag

deploy:
    COPY (+sources/*) /src
    LET tag=$(tar cf - /src | sha1sum | awk '{print $1}')
    WAIT
        BUILD --pass-args +build-image --tag=$tag
    END
    FROM --pass-args core+vcluster-deployer-image
    RUN kubectl patch Versions.formance.com default -p "{\"spec\":{\"auth\": \"${tag}\"}}" --type=merge

deploy-staging:
    BUILD --pass-args core+deploy-staging

openapi:
    COPY ./openapi.yaml .
    SAVE ARTIFACT ./openapi.yaml