FROM node:18-bullseye

WORKDIR /app

COPY package*.json ./

RUN npm ci --force 

COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev"]
