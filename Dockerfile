FROM node:18-alpine

WORKDIR /app

# Install build dependencies for some node modules
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

EXPOSE 4004

CMD ["npm", "start"]
