FROM oven/bun:1.3.13

WORKDIR /app

COPY server/index.ts ./index.ts

RUN mkdir -p /app/data

ENV PORT=8080
ENV DB_PATH=/app/data/commercial.db

EXPOSE 8080

CMD ["bun", "run", "index.ts"]
