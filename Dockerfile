FROM node:18-alpine

# 모든 빌드 도구 설치
RUN apk add --no-cache \
    python3 \
    py3-pip \
    make \
    g++ \
    gcc \
    libc-dev \
    linux-headers \
    sqlite-dev

WORKDIR /app

# package.json 복사
COPY package*.json ./

# npm 업그레이드
RUN npm install -g npm@latest

# 의존성 설치 (verbose 모드)
RUN npm ci --build-from-source --verbose

# 앱 코드 복사
COPY . .

# 데이터 디렉토리 생성
RUN mkdir -p data

# 포트 노출
EXPOSE 3001

# 서버 실행
CMD ["node", "server.js"]