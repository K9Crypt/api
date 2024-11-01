# K9Crypt

K9Crypt allows you to create and share encrypted messages.

## Installation

Follow the steps below to set up K9Crypt:

### Prerequisites
- Node.js (>=12.x)
- MongoDB

### Steps
1. Clone the repository
```bash
git clone https://github.com/k9crypt/api.git
cd api
```
2. Setup `.env` file
```bash
SECRET_KEY=ultra mega super secret key 101
DATABASE_URL=MONGODB_URI
```
3. Install dependencies
```bash
npm install
```
4. Start the server
```bash
node index.js
```

## Usage

### Creating a Room
To create a room, send a POST request to the `/room/create` endpoint with the userId, type (optional, default is 'public'), and password (required for private rooms) parameters in the request body. The response will contain the created room's ID.

### Joining a Room
To join a room, send a POST request to the `/room/join` endpoint with the roomId, userId, and password (required for private rooms) parameters in the request body. The response will contain a message indicating the success of the join operation.

### Leaving a Room
To leave a room, send a POST request to the `/room/leave` endpoint with the roomId and userId parameters in the request body. The response will contain a message indicating the success of the leave operation.

### Sending a Message
To send a message to a room, send a POST request to the `/room/message` endpoint with the roomId, userId, and message parameters in the request body. The response will contain a message indicating the success of the message sending operation.

### Getting Messages
To get the messages of a specific room, send a GET request to the `/room/:roomId/messages` endpoint. The response will contain the decrypted messages of the room.

### Error Handling
If an error occurs, the server will return an appropriate HTTP status code and error message in the response body.

### Warning
Remember, messages are deleted every 2 hours.

## Error Handling
If an error occurs, the server will return an appropriate HTTP status code and error message in the response body.

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.