ARG CUSTOM_NODE_VERSION=16.14.0-alpine3.15

# Create base layer with dependencies
FROM node:$CUSTOM_NODE_VERSION AS dependencies
WORKDIR /test
COPY ["package.json", "./"]
RUN ["npm", "install", "--production"]

# Reduce dependencies' size
RUN npm install modclean -g && \
    rm -rf docs/ coverage/ src/ tests/ typings/ .git/ .github/ *.md && \
    rm -rf node_modules/*/test/ node_modules/*/tests/ && \
    npm prune && \
    modclean -n default:safe --run && \
    npm uninstall -g modclean

FROM softonic/node-prune:latest AS pruner
COPY --from=dependencies /test/node_modules /test/node_modules
RUN node-prune /test/node_modules

# Create final layer
FROM node:$CUSTOM_NODE_VERSION AS production
WORKDIR /test
COPY --from=pruner /test/node_modules ./node_modules

COPY ["./test.js", "./"]

ARG IMG_TAG_VAR=1.0.0
ENV IMG_TAG=$IMG_TAG_VAR

ENV NODE_ENV=development

CMD ["node", "test.js", "--trace-sync-io", "--trace-warnings"]
