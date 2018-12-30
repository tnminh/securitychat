var dbProcess=function(){
    var callbackSuccess=[];
    var inputRequest={
        url:"",
        type:"POST",
        data:{}
    }
    var setData=function(data){
        inputRequest.data=data;
        return this
    }
    var setUrl=function(url){
        inputRequest.url=url;
        return this;
    }

    var setType=function(type){
        inputRequest.type=type;
        return this;
    }
    var onMsg=function(callback){
        callbackSuccess.push(callback);
        return this;
    }

    var run=function(){
            ajax(function(){
                inputRequest.success=function(response){
                    callbackSuccess.forEach(function(callback){
                        callback(response);
                    });
                }
                inputRequest.error=function(error){
                    
                }
                inputRequest.complete= "poll";
                return inputRequest;
            }());
    };

    return {run:run,setData:setData,setUrl:setUrl,onMsg:onMsg,setType:setType};
}


class msg{
    constructor() {
         this.callbackOnMsg=[];
        this.message="";
        this.respMsg="";
        var thisClass=this;
        this.iDb=new dbProcess().onMsg(function(msg){
            thisClass.respMsg=thisClass.processRespMsg(msg);
            thisClass.callbackOnMsg.forEach(function(callback){
                callback(thisClass.respMsg);
            });
        });
        this.iDb.setUrl(thisClass.setUrl());
    }
    onMsg(callback){
        this.callbackOnMsg.push(callback);
        return this;
    }
    processRespMsg(msg){
        return msg;
    }
    processSendMsg(msg){
        return msg;
    }
    setUrl(){
        return"";
    }
    send(){
        var message=this.message;
        this.iDb.setData(this.processSendMsg(message)).run();
    }
    setMsg(msg){
        this.message=msg;
        return this;
    }
}
class waitingMsg extends msg{
    constructor(){
        super();
        var idb=this.iDb;
        var thisClass=this;
        idb.onMsg(function(){
            idb.run();
        })
        idb.setData(thisClass.getKey());
        idb.run();
    }
    getKey(){
        return "";
    }


}
class waitingRSAMsg extends waitingMsg{
    constructor(re,resp){
        super(re,resp);
    }
    getKey(){
        return rsaSecurity.getPemPublicKey();
    }
    setUrl(){
        return"get-rsa-msg";
    }
    processRespMsg(msg){
        return rsaSecurity.decript(msg);
    }

}
class waitingRsaSetupMsg extends msg{
    
    constructor(re,resp){
        super(re,resp);
        this.finishSetupCallback=[];
        var thisClass=this;
        this.onMsg(function(msg){
            rsaSecurity.setServerPublicKey(msg);
            thisClass.finishSetupCallback.forEach(function(callback){
                callback(thisClass.respMsg);
            });
        })
        this.iDb.run();

    }
    setUrl(){
        return"get-rsa-public-key-msg";
    }
    onFinishSetup(callback){
        this.finishSetupCallback.push(callback);
    }
}



class waitingAESMsg extends waitingMsg{
    constructor(re,resp){
        super(re,resp);
    }
    setUrl(){
        return"get-aes-msg";
    }

    processRespMsg(msg){
        return aesSecurity.decryptAes(msg);
    }
}



class sendingRSAMsg extends msg{
    constructor(re,resp){
        super(re,resp);
    }
    setUrl(){
        return"send-rsa-msg";
    }
    processSendMsg(msg){
        return rsaSecurity.encryptFromPublicKey(msg);
    }
}
class waitingAesSetupMsg extends msg{
    constructor(re,resp){
        super(re,resp);
        this.finishSetupCallback=[];
        var thisClass=this;
        this.onMsg(function(msg){
            aesSecurity.setAesKey(msg);
            thisClass.finishSetupCallback.forEach(function(callback){
                callback(thisClass.respMsg);
            });
        })
        var idb=this.iDb;
        thisClass.setMsg(rsaSecurity.getPemPublicKey());
    }
    setUrl(){
        return"get-aes-key-msg";
    }
    onFinishSetup(callback){
        this.finishSetupCallback.push(callback);
    }
    processRespMsg(msg){
        return rsaSecurity.decript(msg);
    }

}
class sendingAesMsg extends msg{
    constructor(re,resp){
        super(re,resp);
    }
    setUrl(){
        return"send-aes-msg";
    }
    processSendMsg(msg){
        return aesSecurity.encryptAES(msg);
    }
}

var aesSecurity=function(){
    var aesKey= "";
    var iv = "0123456789123456";


    var encryptAES=function(data){
        var cipher = forge.cipher.createCipher('AES-CBC', aesKey);
        cipher.start({iv: iv});
        cipher.update(forge.util.createBuffer(data));
        cipher.finish();
        var encrypted = cipher.output.data;
        return encrypted;
    }
    var decryptAes=function(data){
        var decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
        decipher.start({iv: iv});
        decipher.update(forge.util.createBuffer(data));
        var result = decipher.finish(); // check 'result' for true/false
        // outputs decrypted hex
        return decipher.output.data;
    }
    return {
        encryptAES:encryptAES,
        decryptAes:decryptAes,
        setAesKey:function(key){
            aesKey=key;
        }
    }
}();
var rsaSecurity=function(){
    var rsaKeys = forge.pki.rsa.generateKeyPair({bits: 1024});
    var publicKey=rsaKeys.publicKey;
    var privateKey=rsaKeys.privateKey;
    var serverPublickey="";
    var getPemPublicKey=function(){
        return  forge.pki.publicKeyToPem(publicKey);
    }
    var pemToPublickey=function(pemPublicKey){
        return forge.pki.publicKeyFromPem(pemPublicKey)
    }
    var decript=function(encrypted){
        return privateKey.decrypt(encrypted);
    }
    var encryptFromPublicKey=function(data){
        var pKey=pemToPublickey(serverPublickey);
        var encrpyted=pKey.encrypt(data);
        return encrpyted;
    }
    return{
        getPemPublicKey:getPemPublicKey,pemToPublickey:pemToPublickey,decript:decript,encryptFromPublicKey:encryptFromPublicKey,
        setServerPublicKey:function(key){
            serverPublickey=key;
        }
    }
}();
var setup= new waitingRsaSetupMsg();
var setup2= new waitingAesSetupMsg();
setup2.onFinishSetup(function(){
    var msg= new waitingRSAMsg();
    msg.onMsg(function(msg){
        console.log(msg);
    })
    var msg2= new waitingAESMsg();
    msg2.onMsg(function(msg){
        console.log(msg);
    })
});
setup.onFinishSetup(function(){
    setup2.send();
})
var sendRsa= new sendingRSAMsg();
var sendAes= new sendingAesMsg();