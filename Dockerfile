# Use an official Node.js runtime as a parent image
FROM node:18

# Set the working directory inside the container
WORKDIR /usr/src/app

COPY server.js /usr/src/app/server.js
COPY package.json /usr/src/app/package.json

# # Copy package.json and package-lock.json to the working directory
# COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code to the working directory


# Expose the port the app runs on
EXPOSE 3000

CMD ["tail", "-f", "/dev/null"]

# # # Command to run the Node.js server
# CMD ["node", "server.js"]
