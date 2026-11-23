/**
 * 主线程版 nativeSearch：把整段 MtopBuilder.syncRequest() 放到 Android 主线程执行。
 * 假设：SecurityGuard SecException 1927 是因为 Frida RPC 线程上下文异常，
 * 主线程执行可复现 App UI 搜索的签名环境。
 */
function ss(v) { if (v === null || v === undefined) return ''; try { return String(v); } catch (e) { return ''; } }

function doSearch(payload, out) {
  try {
    var Mtop = Java.use('mtopsdk.mtop.intf.Mtop');
    var mtop = null, iid = null, bestScore = -9999;
    var seen = {};
    function score(inst) {
      if (!inst) return;
      var id='',ttid='',utdid='';
      try { id=ss(inst.getInstanceId()); } catch(e){}
      try { ttid=ss(inst.getTtid()); } catch(e){}
      try { utdid=ss(inst.getUtdid()); } catch(e){}
      var key=id+'|'+ttid; if(seen[key])return; seen[key]=true;
      var s=0; var low=(id+' '+ttid).toLowerCase();
      if(low.indexOf('eleme')>=0||low.indexOf('koubei')>=0||low.indexOf('xianyu')>=0)s-=1000;
      if(id==='INNER'||id==='MTOP_ID_TAOBAO')s+=100;
      if(ttid.indexOf('taobao_android')>=0)s+=60;
      if(utdid.length>=16)s+=20;
      if(s>bestScore){bestScore=s;mtop=inst;iid=id;}
    }
    Java.choose('mtopsdk.mtop.intf.Mtop', { onMatch: function(i){score(i);}, onComplete: function(){} });
    ['INNER','MTOP_ID_TAOBAO',''].forEach(function(id){ try{score(Mtop.getInstance(id));}catch(e){} });
    out.instanceId=iid;
    if(!mtop){out.error='no mtop';return;}

    var MtopRequest = Java.use('mtopsdk.mtop.domain.MtopRequest');
    var mreq = MtopRequest.$new();
    mreq.setApiName(payload.api);
    mreq.setVersion(payload.version || '1.0');
    mreq.setData(payload.data);
    try { mreq.setNeedSession(false); } catch(e){}

    var HashMap = Java.use('java.util.HashMap');
    var hdr = HashMap.$new();
    var H = payload.headers || {};
    Object.keys(H).forEach(function(k){hdr.put(k,String(H[k]));});

    var MB = Java.use('mtopsdk.mtop.intf.MtopBuilder');
    var ctor = MB.$new.overload('mtopsdk.mtop.intf.Mtop','mtopsdk.mtop.domain.MtopRequest','java.lang.String');
    var ttid = payload.ttid || '231200@taobao_android_10.69.10';
    var builder = ctor.call(MB, mtop, mreq, ttid);
    builder.headers(hdr);
    if(payload.method==='POST'){
      var ME = Java.use('mtopsdk.mtop.domain.MethodEnum');
      builder.reqMethod(ME.POST.value);
      try{builder.allowSwitchToPOST(true);}catch(e){}
    }
    builder.ttid(ttid);
    var resp = builder.syncRequest();
    out.step='done';
    if(resp===null){out.error='null resp';return;}
    try{out.retCode=ss(resp.getRetCode());}catch(e){}
    try{out.retMsg=ss(resp.getRetMsg());}catch(e){}
    try{var jo=resp.getDataJsonObject();out.data=jo?ss(jo.toString()):null;}catch(e){}
    try{out.raw=ss(resp.toString()).substring(0,600);}catch(e){}
  } catch(e) { out.error=String(e); out.step=out.step||'ex'; }
}

// 用 registerClass 实现 Runnable（frida-java-bridge 17 不能用对象字面量 new 接口）
var SearchRunnable = null;
function ensureRunnable() {
  if (SearchRunnable) return;
  try {
    SearchRunnable = Java.registerClass({
      name: 'com.rea.SearchRunnable',
      implements: [Java.use('java.lang.Runnable')],
      methods: {
        run: [{
          returnType: 'void', argumentTypes: [],
          implementation: function () {
            try { doSearch(globalThis.__reaPayload, globalThis.__reaOut); }
            catch (e) { globalThis.__reaOut.error = 'runnable: ' + e; }
            try { globalThis.__reaLatch.countDown(); } catch (e) {}
          }
        }]
      }
    });
  } catch (e) {
    // 已注册过则忽略
  }
}

rpc.exports = {
  nativeSearchOnMain: function (payloadJson) {
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch(e) { return JSON.stringify({error:'bad payload'}); }
    var out = {error:null, step:'start', thread:'main'};
    var result = Java.perform(function () {
      try {
        var Looper = Java.use('android.os.Looper');
        var Handler = Java.use('android.os.Handler');
        var CountDownLatch = Java.use('java.util.concurrent.CountDownLatch');
        var TimeUnit = Java.use('java.util.concurrent.TimeUnit');
        ensureRunnable();
        var mainLooper = Looper.getMainLooper();
        var handler = Handler.$new(mainLooper);
        var latch = CountDownLatch.$new(1);
        globalThis.__reaPayload = payload;
        globalThis.__reaOut = out;
        globalThis.__reaLatch = latch;
        handler.post(SearchRunnable.$new());
        latch.await(60, TimeUnit.SECONDS.value);
      } catch (e) { out.error = 'main-thread: ' + e; }
      return out;
    });
    return JSON.stringify(result || out);
  },
  ping: function(){ return 'pong'; }
};
