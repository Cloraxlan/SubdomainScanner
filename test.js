const https = require('https');

https.get('https://http-observatory.security.mozilla.org//api/v1/analyze?host=analytics.google.com', (resp) => {
  let data = '';

  // A chunk of data has been recieved.
  resp.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received. Print out the result.
  resp.on('end', () => {
    console.log(JSON.parse(data).grade);
  });

}).on("error", (err) => {
  console.log("Error: " + err.message);
});
request("https://http-observatory.security.mozilla.org//api/v1/analyze?host="+subs[o], {
