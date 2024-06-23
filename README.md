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

### Creating a message
To create a message, send a POST request to the `/create` endpoint with the message in the body. The response will contain the ID of the message.

### Retrieving a message
To retrieve a message, send a GET request to the `/view` endpoint with the ID of the message in the URL. The response will contain the encrypted message.

### Warning
Remember, messages are deleted every 2 hours.

## Error Handling
If an error occurs, the server will return an appropriate HTTP status code and error message in the response body.

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.