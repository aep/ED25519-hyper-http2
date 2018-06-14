const http2 = require('http2');
const fs = require('fs');

const server = http2.createServer();
server.on('stream', (stream, headers) => {
  stream.respond({
    'content-type': 'text/html',
    ':status': 200
  });
  stream.on('data', (chunk) => {
    console.log("got data", chunk);
    stream.write(chunk);
  });
});
server.listen(3000);
