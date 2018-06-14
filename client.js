const http2 = require('http2');
const client = http2.connect('http://localhost:3000');
const req = client.request({ ':method': 'POST', ':path': '/' });
req.on('data', (chunk) => {
  console.log("got data", chunk.length);
});
req.on('end', () => client.destroy());
req.write('bla');
setInterval(function() {
  req.write('many bytes go round and round and round so many nice bytes \
  yes yes bla bla horse likes bytes. look at my bytes my bytes are amazing \
  give it a lick tastes just like anus \
  yes yes bla bla horse likes bytes. look at my bytes my bytes are amazing \
  give it a lick tastes just like anus \
  yes yes bla bla horse likes bytes. look at my bytes my bytes are amazing \
  give it a lick tastes just like anus \
  yes yes bla bla horse likes bytes. look at my bytes my bytes are amazing \
  give it a lick tastes just like anus \
  yes yes bla bla horse likes bytes. look at my bytes my bytes are amazing \
  give it a lick tastes just like anus \
  yes yes bla bla horse likes bytes. look at my bytes my bytes are amazing \
  give it a lick tastes just like anus \
  yes yes bla bla horse likes bytes. look at my bytes my bytes are amazing \
  give it a lick tastes just like anus \
  yes yes bla bla horse likes bytes. look at my bytes my bytes are amazing \
  give it a lick tastes just like anus \
  yes yes bla bla horse likes bytes. look at my bytes my bytes are amazing \
  give it a lick tastes just like anus \
  yes yes bla bla horse likes bytes. look at my bytes my bytes are amazing \
  give it a lick tastes just like anus');
}, 1000);
