# Typescript typeauth library

@typeauth/api-node is a TypeScript library that simplifies the authentication process for your API applications running in node. It's a wrapper around the authentication API endpoint.

## Features

- Simple and intuitive API for authentication
- Customizable options for initialization
- Support for custom token headers
- Telemetry data collection (can be disabled)
- Customizable opetion for retry and delay
- Comprehensive error handling and documentation references

## Installation

You can install typeauth using npm:

```bash
npm install @typeauth/api-node
```

## Usage

First, import the `typeauth` class from the library:

```typescript
import { typeauth } from "@typeauth/api-node";
```

Then, initialize the `typeauth` instance with your desired options:

```typescript
const typeauth = new typeauth({
  appId: "YOUR_APP_ID",
  // Optional configuration options
  baseUrl: "https://api.typeauth.com",
  tokenHeader: "Authorization",
  disableTelemetry: false,
  maxRetries: 5,
  retryDelay: 2000,
});
```

To authenticate a request, call the `authenticate` method with the request object:

```typescript
const express = require("express");
const { Typeauth } = require("@typeauth/api-node");

const app = express();

// Initialize the Typeauth client
const typeauth = new Typeauth({
  appId: "YOUR_APP_ID",
  // Other options if needed
});

// Middleware to authenticate POST requests
const authenticatePostRequest = async (req, res, next) => {
  if (req.method === "POST") {
    const { result, error } = await typeauth.authenticate(req);

    if (error) {
      console.error(error.message);
      return res.status(401).json({ error: "Unauthorized" });
    }

    return res.status(200).json({ message: "OK" });
    next();
  } else {
    // If not a POST request, proceed to the next middleware or route handler
    next();
  }
};

// Apply the authentication middleware to all routes
app.use(authenticatePostRequest);
```

## Configuration Options

The `typeauth` constructor accepts an options object with the following properties:

- `appId` (required): Your typeauth application ID.
- `tokenHeader` (optional): The name of the header that contains the authentication token. Defaults to `'Authorization'`.
- `disableTelemetry` (optional): Set to `true` to disable telemetry data collection. Defaults to `false`.
- `maxRetries` (optional): The number of tries in case the typeauth API is not responding. Defaults to `3`.
- `retryDelay` (optional): // The number of milisendseconds before send another requests. Defauls to `1000`.

## Error Handling

The `authenticate` method returns an object with either a `result` property (on success) or an `error` property (on failure). The `error` object contains the following properties:

- `message`: A description of the error.
- `docs`: A URL to the relevant documentation page for more information about the error.

Make sure to handle errors appropriately in your application logic.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvement, please open an issue or submit a pull request on the this GitHub repository.
