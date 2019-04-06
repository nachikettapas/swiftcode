const express = require('express')
const path = require('path')
const logger = require('morgan')
const cookieParser = require('cookie-parser')
//const bodyParser = require('body-parser')
var busboy = require('connect-busboy');
const fileUpload = require('express-fileupload')
const cors = require('cors')
const request = require('request');
const fs = require('fs');

//For file upload to next processing redirection
const url = require('url'); 

//For POST request
const endpoint = 'http://localhost:5000/insert'

// CRYPTOGRAPHY
var privateKey = "e111df10505992ec9245ce43c8663e244f4741f6b15429d669a35c40abf35297";
let elliptic = require('elliptic');
let sha3 = require('js-sha3');
let ec = new elliptic.ec('secp256k1');

const app = express()

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'jade')

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'))
app.use(cors())
app.use(busboy({
  highWaterMark: 1024 * 1024 * 1024, // Set 1GB buffer
})); 
/*app.use(bodyParser.json())
app.use(
  bodyParser.urlencoded({
    extended: false,
  }),
)*/
//app.use(cookieParser())
//app.use(fileUpload())
app.use('/public', express.static(__dirname + '/public'))

app.post('/upload', (req, res, next) => {
  var fileSign; // = req.body.file_sign;
  var fileNameSign; // = req.body.filename_sign;
  var fields = {};

  req.pipe(req.busboy); // Pipe it trough busboy

  req.busboy.on('field', (fieldname, val) => {
    fields[fieldname] = val;
  });

  req.busboy.on('file', (fieldname, file, fileName) => {
      console.log(`Upload of '${fileName}' started`);

      const path = `${__dirname}/public/files/${fileName}`;

      // Create a write stream of the new file
      const fstream = fs.createWriteStream(path);

      // Pipe it trough
      file.pipe(fstream);

      // On finish of the upload
      fstream.on('close', () => {
          console.log(`Upload of '${fileName}' finished`);
          fileSign = fields["file_sign"];
          fileNameSign = fields["filename_sign"];

          //Reading file content for verification
          let fileBuffer = fs.readFileSync(path);
          let fileContent = fileBuffer.toString('utf8');
  
          //File content verification
          let fileHash = sha3.keccak256(fileContent);
          let hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
          let pubKeyRecovered = ec.recoverPubKey(hexToDecimal(fileHash), JSON.parse(fileSign), JSON.parse(fileSign).recoveryParam, "hex");
          let validFile = ec.verify(fileHash, JSON.parse(fileSign), pubKeyRecovered);
          console.log("File Content valid?", validFile);

          //File name verification
          let fileNameHash = sha3.keccak256(fileName);
          pubKeyRecovered = ec.recoverPubKey(hexToDecimal(fileNameHash), JSON.parse(fileNameSign), JSON.parse(fileNameSign).recoveryParam, "hex");
          let validFileName = ec.verify(fileNameHash, JSON.parse(fileNameSign), pubKeyRecovered);
          console.log("File Name valid?", validFileName);

          let keyPair = ec.keyFromPrivate(privateKey);
          let pubKey = keyPair.getPublic();

          //request.post('http://localhost:5000/insert', { json: { id: 0, sender: pubKeyRecovered.encodeCompressed("hex"), receiver: pubKey.encodeCompressed("hex"), data: {filesign: fileSign, filenamesign: fileNameSign}}}, function (req, res) {
          request.post('http://localhost:5000/insert', { json: { id: 0, sender: pubKeyRecovered, receiver: pubKey, data: {filesign: fileSign, filenamesign: fileNameSign}}}, function (error, output) {
            if(error) {
              res.status(400);
            }  
            console.log(output.body.transactionhash);
            
            //CURL equivalent code to get authorization token
            var token;
            var headers = {'Content-Type': 'application/json'};
            //var dataString = '{ "auth": { "identity": { "methods": ["password"], "password": { "user": { "name": "admin", "domain": { "id": "default" }, "password": "03192d7066da4692" } } }, "scope": { "project": { "name": "admin", "domain": { "id": "default" } } } } }';
            var dataString = '{ "auth": { "identity": { "methods": ["password"], "password": { "user": { "name": "admin", "domain": { "id": "default" }, "password": "d7921d93a7c54ebc" } } }, "scope": { "project": { "name": "admin", "domain": { "id": "default" } } } } }';
            //var options = {url: 'http://192.168.2.16:5000/v3/auth/tokens', method: 'POST', headers: headers, body: dataString};
            var options = {url: 'http://172.17.6.73:5000/v3/auth/tokens', method: 'POST', headers: headers, body: dataString};
            function callback(error, response, body) {
                if (!error) {
                  token = response.headers["x-subject-token"];
                    var headers = {'Content-Length': '0', 'X-Auth-Token': token};
                    var options = {url: 'http://172.17.6.73:8080/v1/AUTH_b1a6434330ae4a6a84f7fa3f4928e4b4/container1', method: 'PUT', headers: headers};
                  
                    function callback(error, response, body) {
                        if (!error) {
                          var headers = {'Content-Type': 'text/html; charset=UTF-8', 'X-Auth-Token': token};
                          var options = {url: 'http://172.17.6.73:8080/v1/AUTH_b1a6434330ae4a6a84f7fa3f4928e4b4/container1/' + fileName, method: 'PUT', headers: headers, body: fileContent};
                        
                          function callback(error, response, body) {
                              if (!error) {
                                  //console.log(body);
                                  //console.log(JSON.stringify(response.headers));
                                  var headers = {'X-Auth-Token': token};
                                  var options = {url: 'http://172.17.6.73:8080/v1/AUTH_b1a6434330ae4a6a84f7fa3f4928e4b4/container1/' + fileName, headers: headers};
                                
                                  function callback(error, response, body) {
                                      if (!error) {
                                          //console.log(JSON.stringify(response.headers));

                                          //Logic to encrypt the etag and x-timestamp and send it to client
                                          var resultData = { etag: response.headers["etag"], xtimestamp: response.headers["x-timestamp"]};
                                          let resultSign = ec.sign(JSON.stringify(resultData), privateKey, "hex", {canonical: true});
                                          //console.log(resultSign);

                                          res.send(JSON.stringify({resData: resultData, resSign: resultSign}));
                                          return res.end();
                                      } else {
                                        console.log('error' + error.toString());
                                      }
                                  }
                                  request(options, callback);
                              } else {
                                console.log('error' + error.toString());
                              }
                          }                
                          request(options, callback);
                        } else {
                          console.log('error' + error.toString());
                        }
                    }
                    request(options, callback);

                } else {
                  console.log('error' + error.toString());
                }
            }
            request(options, callback);
      });
    });
  });
})

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  const err = new Error('Not Found')
  err.status = 404
  next(err)
})

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message
  res.locals.error = req.app.get('env') === 'development' ? err : {}

  // render the error page
  res.status(err.status || 500)
  res.render('error')
})

module.exports = app