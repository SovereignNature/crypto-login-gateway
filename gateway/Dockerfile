ARG CUSTOM_NODE_VERSION=16.14.0-alpine3.15

# Create base layer with dependencies
FROM node:$CUSTOM_NODE_VERSION AS dependencies
WORKDIR /login-api
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
COPY --from=dependencies /login-api/node_modules /login-api/node_modules
RUN node-prune /login-api/node_modules

# Create final layer
FROM node:$CUSTOM_NODE_VERSION AS production
WORKDIR /login-api
COPY --from=pruner /login-api/node_modules ./node_modules

COPY ["./main.js", "."]

ARG IMG_TAG_VAR=1.0.0
ENV IMG_TAG=$IMG_TAG_VAR

#ENV NODE_ENV=development
ENV NODE_ENV=production

EXPOSE 80/tcp

CMD ["node", "main.js"]
