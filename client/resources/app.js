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
                return inputRequest;
            }());
    };

    return {run:run,setData:setData,setUrl:setUrl,onMsg:onMsg,setType:setType};
}
var rq=new dbProcess().setUrl("/get-msg");
rq.onMsg(function(msg){
    console.log(msg);
    rq.run();
}).run();
