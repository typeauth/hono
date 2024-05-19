/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
};


// const url = `${this.baseUrl}/authenticate`;
// const body = JSON.stringify({
//   token,
//   appID: this.appId,
//   telemetry: this.disableTelemetry
//     ? undefined
//     : {
//         url: req.url,
//         method: req.method,
//         headers: req.headers,
//         ipaddress: req.socket?.remoteAddress ?? "",
//         timestamp: Date.now(),
//       },
// });
