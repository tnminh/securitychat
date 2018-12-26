var fs = require("fs");
var http = require("http");
var url = require("url");
var forge=require("node-forge");

var server = function () {
    var STORAGELOCATION = 'Storage/data.txt';
    var server = http.createServer();
    server.listen(8888);
    server.on('request', function (request, response) {
        try {
            var pathname = url.parse(request.url).pathname;
            //plugin
            if (pathname.includes("/resources/")) {
                var txt = fs.readFileSync("client"+pathname, "utf8");
                response.write(txt);
                response.end();
                return;
            }
             //html
             if (pathname === "/") {
                var txt = fs.readFileSync("client/"+ "html/app.html", "utf8");
                response.write(txt);
                response.end();
                return;
            }
        }
        catch (err) {
            console.log(err);
            response.write("Error");
            response.end();
        }

    });
    return server;
}();

class msg{
    constructor(re,resp) {
        this.request=re;
        this.response=resp;
        this.message="";
        this.bodyMsgPromise=this.getBodyMsgPromise();
        this.comingBodyMsg="";

    }
    send(){
        var message=this.message;
        this.response.write(message);
        this.response.end();
    }
    setMsg(msg){
        this.message=msg;
        return this;
    }
    getBodyMsgPromise(){
        var request=this.request;
        var thisClass=this;
        var promise= new Promise(function(resolve,reject){
            let body = [];
            request.on('data', (chunk) => {
                body.push(chunk);
            }).on('end', () => {
                var msg = Buffer.concat(body).toString();
                thisClass.comingBodyMsg=msg;
                resolve(msg);
            });
        })
        return promise;
    }
}
class waitingMsg extends msg{
    constructor(re,resp){
        super(re,resp);
        this.responseMsg();
    }
    responseMsg(){
        var thisClass=this;
        msgContainer.onNewMsg(function(msg){
            thisClass.setMsg(msg).send();
        })
    }

}
class waitingRSAMsg extends waitingMsg{
    constructor(re,resp){
        super(re,resp);
    }
    send(){
        thisClass=this;
        thisClass.bodyMsgPromise.then(function(){
            var pemPublicKey = thisClass.comingBodyMsg;
            var encryptedMsg=rsaSecurity.encryptFromPublicKey(pemPublicKey,thisClass.message);
            thisClass.response.write(encryptedMsg);
            thisClass.response.end();
        })
    }
}
class waitingRsaSetupMsg extends waitingMsg{
    constructor(re,resp){
        super(re,resp);
    }
    responseMsg(){
        this.setMsg(rsaSecurity.getPemPublicKey()).send();
    }
}


class waitingAESMsg extends waitingMsg{
    constructor(re,resp){
        super(re,resp);
    }
    send(msg){
        thisClass=this;
        encryptedMsg.aesSecurity.encryptAES(thisClass.message);
        thisClass.response.write(encryptedMsg);
        thisClass.response.end();
    }
}
class waitingAesSetupMsg extends waitingRSAMsg{
    constructor(re,resp){
        super(re,resp);
    }
    responseMsg(){
        this.send(aesSecurity.getAesKey());
    }
}

class sendingMsg extends msg{
    constructor(re,resp){
        super(re,resp);
        var msgClass=this;
        msgClass.bodyMsgPromise.then(function(msg){
            msgClass.setMsg("success").send();
            msgContainer.put(msgClass.processComingMsg(msg));
        })
    }
    processComingMsg(msg){
        return msg;
    }

}
class sendingRSAMsg extends sendingMsg{
    constructor(re,resp){
        super(re,resp);
    }
    processComingMsg(msg){
        return rsaSecurity.decript(msg);
    }
}
class sendingAesMsg extends sendingMsg{
    constructor(re,resp){
        super(re,resp);
    }
    processComingMsg(msg){
        return aesSecurity.decryptAes(msg);
    }
}
var msgContainer=function(){
    var onNewMsgCallbacks=[];
    var messageStore=[];
    var onNewMsg=function(callback){
        onNewMsgCallbacks.push(callback);
    }
    var sendAll=function(msg){
        onNewMsgCallbacks.forEach(function(callback,index){
            callback(msg);
        })
    }
    var put=function(msg){
        messageStore.push(msg);
        sendAll(msg);
        onNewMsgCallbacks=[];
    }
    return {onNewMsg:onNewMsg,put:put};
}();

server.on('request', function (request, response) {
    try {
        var pathname = url.parse(request.url).pathname;

         //html
        if (pathname === "/get-msg") {
            new waitingMsg(request,response);
        }
        if(pathname==="/send-msg"){
            new sendingMsg(request,response);
        }
        if(pathname==="/get-rsa-msg"){
            new waitingRSAMsg(request,response);
        }
        if(pathname==="/send-rsa-msg"){
            new sendingRSAMsg(request,response);
        }
        if(pathname==="/get-aes-msg"){
            new waitingAESMsg(request,response);
        }
        if(pathname==="/send-aes-msg"){
            new sendingAesMsg(request,response);
        }
        if(pathname==="/get-rsa-public-key-msg"){
            new waitingRsaSetupMsg(request,response);
        }
        if(pathname==="/get-aes-key-msg"){
            new waitingRsaSetupMsg(request,response);
        }
    }
    catch (err) {
        console.log(err);
        response.write("Error");
        response.end();
    }

});
var aesSecurity=function(){
    var aesKey= forge.random.getBytesSync(16);
    var iv = "0123456789123456";
    var cipher = forge.cipher.createCipher('AES-CBC', aesKey);
    cipher.start({iv: iv});
    var decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
    decipher.start({iv: iv});

    var encryptAES=function(data){
        cipher.update(forge.util.createBuffer(data));
        cipher.finish();
        var encrypted = cipher.output.data;
        return encrypted;
    }
    var decryptAes=function(data){
        decipher.update(forge.util.createBuffer(data));
        var result = decipher.finish(); // check 'result' for true/false
        // outputs decrypted hex
        return decipher.output.data;
    }
    return {
        encryptAES:encryptAES,
        decryptAes:decryptAes,
        getAesKey:function(){
            return aesKey;
        }
    }
}();
var rsaSecurity=function(){
    var rsaKeys = forge.pki.rsa.generateKeyPair({bits: 1024});
    var publicKey=rsaKeys.publicKey;
    var privateKey=rsaKeys.privateKey;
    var getPemPublicKey=function(){
        return  forge.pki.publicKeyToPem(publicKey);
    }
    var pemToPublickey=function(pemPublicKey){
        return forge.pki.publicKeyFromPem(pem)
    }
    var decript=function(encrypted){
        return privateKey.decrypt(encrypted);
    }
    var encryptFromPublicKey=function(pemPublicKey,data){
        var pKey=pemToPublickey(pemPublicKey);
        var encrpyted=pkey.encrypt(data);
        return encrpyted;
    }
    return{
        getPemPublicKey:getPemPublicKey,pemToPublickey:pemToPublickey,decript:decript,encryptFromPublicKey:encryptFromPublicKey
    }
}()