FROM node:18

WORKDIR /app

COPY package*.json ./

RUN npm ci

COPY . .

RUN mkdir -p data

EXPOSE 3001

CMD ["node", "server.js"]