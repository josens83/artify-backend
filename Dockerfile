FROM node:18-alpine

# 빌드 도구 설치
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    gcc \
    musl-dev

WORKDIR /app

# package.json 복사
COPY package*.json ./

# 의존성 설치
RUN npm ci --build-from-source

# 앱 복사
COPY . .

# 데이터 디렉토리 생성
RUN mkdir -p data

EXPOSE 3001

CMD ["node", "server.js"]
