/*
 * 真机签名 RPC：把淘宝 App 内的 signRequest / getSecurityFactors 暴露给外部签名后端。
 *
 * 加载方式（Frida 17 + 已运行的 frida-server）：
 *   frida -U -f com.taobao.taobao -l tools/frida/rpc_sign.js --no-pause
 * 或由 tools/frida_rpc_bridge.py attach 后加载（推荐，桥接服务会自动重连）。
 *
 * RPC 导出（frida-python 侧用同名 snake_case 调用）：
 *   status()                 -> JSON 字符串，组件就绪状态
 *   deviceInfo()             -> JSON 字符串，真机 utdid/deviceId/ttid/umt 等
 *   signRequest(payloadJson) -> JSON 字符串，真机四头 {x-sign,x-sgext,x-mini-wua,x-umt,...}
 *   signLegacy(payloadJson)  -> JSON 字符串，老协议 signRequest 单串 {sign:...}
 *
 * 对应 smali 链路（10.69.10）：
 *   tb/n9f.r(...) -> IUnifiedSecurityComponent.getSecurityFactors(HashMap) -> 四头
 *   tb/n9f.l(...) -> ISecureSignatureComponent.signRequest(ctx, authCode) -> 单串
 *
 * 重要：本脚本只做「调用用户自己设备上已安装的 App 的签名能力」，
 * 不破解、不伪造、不绕过风控；使用者需自行持有合法设备与账号授权。
 */

'use strict';

var C = {
  appKey: '21646297',
  lastInput: '',          // 最近一次真机 70102 INPUT（22 段）
  factorTemplate: null,   // 最近一次 getSecurityFactors 入参 Map 的快照
  unifiedComp: null,
  signComp: null,
  innerSign: null,
  requestCtx: null,
  paramBuilder: null,
  mgr: null,
  instanceId: '',
  authCode: '',
  initialized: false,
  lastRealApi: '',
  lastRealArgs: [],
  lastRealParams: {},
  lastRealParamsAfter: {},
  lastRealResult: {},
  headerCapture: null,    // HttpURLConnection.setRequestProperty 抓到的真实 x-* 头
  headerCaptureCount: 0,
  netHeaders: null,       // 网络层抓到的真实 MTOP 请求头（四头 ground truth）
  netUrl: '',
  netHeaderCount: 0,
  successHeads: null,     // 最近一次真机 r() 成功产出的四头（含 x-mini-wua/x-sgext/sign）
  successApi: '',
  successUseWua: false,
  successRArgs: null,     // 成功那次的原始 Java 参数对象（供重放）
  successRThis: null,
  rCallCount: 0,
  rSuccessCount: 0,
  lastRealHeads: null,    // 最近一次真机 buildParams 产出的四头快照（最保真）
  lastRealHeadsTime: 0,
  last_f: null,
  last_g: null,
  sdkSign: null,
  jnicLog: [],
  jnicInstance: null,
  jnicArgs: [],
  jnicRet: {},
  device: {},
  hookStatus: [],
  native70102: { attached: false, fnPtr: '', classGlobal: null, calls: 0, lastArgs: [], lastRet: '' },
  ready: false
};

/**
 * Native 层 70102 抓包：App 实际通过 JNICLibrary.doCommandNative 的 native 实现签四头，
 * Java.use('...JNICLibrary') 在某些 ClassLoader/时机下抓不到，所以直接在 JNI 函数指针上 attach。
 */
function nJniFn(env, index, ret, args) {
  var vtable = env.readPointer();
  return new NativeFunction(vtable.add(index * Process.pointerSize).readPointer(),
    ret || 'pointer', args || ['pointer', 'pointer', 'pointer']);
}

function nJstring(env, jstr) {
  if (!jstr || jstr.isNull()) return 'null';
  try {
    var getChars = nJniFn(env, 169, 'pointer', ['pointer', 'pointer', 'pointer']);
    var rel = nJniFn(env, 170, 'void', ['pointer', 'pointer', 'pointer']);
    var c = getChars(env, jstr, ptr(0));
    var s = (!c || c.isNull()) ? 'null' : c.readUtf8String();
    try { rel(env, jstr, c); } catch (e) {}
    return s;
  } catch (e) { return '<jstring-error:' + e + '>'; }
}

function nJobjectToString(env, obj) {
  if (!obj || obj.isNull()) return 'null';
  try {
    var getClass = nJniFn(env, 31, 'pointer', ['pointer', 'pointer']);
    var getMid = nJniFn(env, 33, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
    var callObj = nJniFn(env, 34, 'pointer', ['pointer', 'pointer', 'pointer']);
    var clazz = getClass(env, obj);
    if (!clazz || clazz.isNull()) return '<no-class>';
    var mid = getMid(env, clazz, Memory.allocUtf8String('toString'),
      Memory.allocUtf8String('()Ljava/lang/String;'));
    if (!mid || mid.isNull()) return '<no-mid>';
    return nJstring(env, callObj(env, obj, mid));
  } catch (e) { return '<jobject-error:' + e + '>'; }
}

function nDumpObjectArray(env, arr) {
  var out = [];
  try {
    var lenFn = nJniFn(env, 171, 'int32', ['pointer', 'pointer']);
    var getFn = nJniFn(env, 173, 'pointer', ['pointer', 'pointer', 'pointer']);
    var n = lenFn(env, arr);
    for (var i = 0; i < n; i++) {
      var elem = getFn(env, arr, ptr(i));
      // SecurityGuard 70102 的参数是 String[]，这里只做 GetStringUTFChars，
      // 不调用 toString()/Java 方法，避免 native 入口处触发 Java 重入。
      out.push(nJstring(env, elem));
    }
  } catch (e) { out.push('dump-error:' + e); }
  return out;
}

function attachNative70102(fnPtr) {
  if (C.native70102.attached) return;
  C.native70102.fnPtr = String(fnPtr);
  try {
    Interceptor.attach(fnPtr, {
      onEnter: function (args) {
        this.cmd = args[2].toInt32();
        if (this.cmd !== 70102) return;
        this.env = args[0];
        this.argsArr = args[3];
        if (!C.native70102.classGlobal || C.native70102.classGlobal.isNull()) {
          try {
            var newGlobal = nJniFn(args[0], 21, 'pointer', ['pointer', 'pointer']);
            C.native70102.classGlobal = newGlobal(args[0], args[1]);
          } catch (e) {}
        }
        C.native70102.calls++;
        // 不在 native 入口读参数：JNI 读字符串会触发 ART 检查，启动阶段有概率崩溃。
        // 参数模板由上一轮已验证的抓包结果提供，这里只保留函数指针和 class 引用。
        // C.native70102.lastArgs = nDumpObjectArray(args[0], args[3]);
      },
      onLeave: function (retval) {
        if (this.cmd !== 70102) return;
        // 不在 native 返回回调里做 JNI 字符串转换；后台线程上会触发 ART JNI 检查崩溃。
        C.native70102.lastRet = String(retval);
      }
    });
    C.native70102.attached = true;
    log('native70102 dump attached at ' + fnPtr);
  } catch (e) { C.hookStatus.push('native70102 attach: ' + e); }
}

function installNative70102Dump() {
  // hook_full_bundle.js 在 RegisterNatives 时已经捕获过 native 函数指针。
  if (globalThis.__sgDoCommandNative) {
    Java.perform(function () { attachNative70102(globalThis.__sgDoCommandNative); });
    return;
  }
  // 兜底：若本脚本先于 RegisterNatives 加载，这里自行等一次。
  var tries = 0;
  var timer = setInterval(function () {
    if (globalThis.__sgDoCommandNative) {
      clearInterval(timer);
      Java.perform(function () { attachNative70102(globalThis.__sgDoCommandNative); });
    } else if (++tries > 300) {
      clearInterval(timer);
      C.hookStatus.push('native70102 dump: no fnPtr');
    }
  }, 100);
}

function log(s) { console.log('[rpc-sign] ' + s); }

function safeStr(o) {
  try { return o === null || o === undefined ? '' : String(o); } catch (e) { return ''; }
}

/** SecException 的 message 常为空，错误码才是关键线索 */
function errDetail(e) {
  var s = String(e);
  try { s += ' code=' + e.getErrorCode(); } catch (_) {}
  try { s += ' class=' + e.getClass().getName(); } catch (_) {}
  return s;
}

function mapToObject(map) {
  var out = {};
  try {
    var keys = map.keySet().toArray();
    for (var i = 0; i < keys.length; i++) {
      var k = safeStr(keys[i]);
      var v = map.get(keys[i]);
      out[k] = v === null || v === undefined ? '' : safeStr(v);
    }
  } catch (e) { out['_error'] = String(e); }
  return out;
}

function objectToMap(obj) {
  var HM = Java.use('java.util.HashMap');
  var m = HM.$new();
  if (!obj || typeof obj !== 'object') return m;
  Object.keys(obj).forEach(function (k) {
    var v = obj[k];
    if (v === null || v === undefined) return;
    if (typeof v === 'number' && Math.floor(v) === v) {
      m.put(k, Java.use('java.lang.Integer').valueOf(v));
    } else if (typeof v === 'boolean') {
      m.put(k, Java.use('java.lang.Boolean').valueOf(v));
    } else {
      m.put(k, String(v));
    }
  });
  return m;
}

function cloneMap(src) {
  if (!src) return null;
  try {
    var HM = Java.use('java.util.HashMap');
    var m = HM.$new(src);
    return m;
  } catch (e) {
    log('cloneMap fail ' + e);
    return null;
  }
}

/** SecurityGuard 类常被插件 ClassLoader 加载，默认 factory 找不到，需按 loader 取 factory */
function factoryFor(className) {
  try { Java.use(className); return Java.classFactory; } catch (e) {}
  try {
    var loaders = Java.enumerateClassLoadersSync();
    for (var i = 0; i < loaders.length; i++) {
      try {
        if (loaders[i].loadClass(className)) return Java.ClassFactory.get(loaders[i]);
      } catch (e) {}
    }
  } catch (e) {}
  return null;
}

function getContext() {
  try {
    return Java.use('com.taobao.tao.Globals').getApplication();
  } catch (e) {}
  try {
    return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  } catch (e) {}
  return null;
}

/** 从运行中的 InnerSignImpl 实例取真机 SecurityGuard 组件（Java.choose 找活实例） */
function ensureFromMtop() {
  try {
    Java.choose('tb/n9f', {
      onMatch: function (inst) {
        try {
          if (!C.unifiedComp && inst.f.value) C.unifiedComp = inst.f.value;
        } catch (e) {}
        try {
          if (!C.signComp && inst.c.value) {
            C.mgr = inst.c.value;
            C.signComp = C.mgr.getSecureSignatureComp();
          }
        } catch (e) {}
        if (C.unifiedComp && C.signComp) return 'stop';
        if (C.innerSign) return;
        C.innerSign = inst;
        C.hookStatus.push('n9f.f: ' + (C.unifiedComp ? 'ok' : 'null'));
        C.hookStatus.push('n9f.c: ' + (C.signComp ? 'ok' : 'null'));
        try {
          var cfg = inst.a.value;  // tb/o30 -> MtopConfig
          if (cfg) {
            C.instanceId = safeStr(cfg.instanceId.value);
            C.appKey = safeStr(cfg.appKey.value) || C.appKey;
            C.device.appKey = C.appKey;
            C.authCode = safeStr(cfg.wuaAuthCode && cfg.wuaAuthCode.value
              ? cfg.wuaAuthCode.value : cfg.authCode.value);
            try { C.device.utdid = safeStr(cfg.utdid.value) || C.device.utdid; } catch (e) {}
            try { C.device.deviceId = safeStr(cfg.deviceId.value) || C.device.deviceId; } catch (e) {}
            try { C.device.ttid = safeStr(cfg.ttid.value) || C.device.ttid; } catch (e) {}
          }
        } catch (e) { C.hookStatus.push('n9f.cfg: ' + e); }
        return;
      },
      onComplete: function () {}
    });
    C.ready = !!(C.unifiedComp || C.signComp);
  } catch (e) { C.hookStatus.push('ensureFromMtop: ' + e); }
  return C.ready;
}

/** 取真机组件实例（不 hook、不修改，仅调用） */
function ensureComponents() {
  if (C.unifiedComp && C.signComp) return true;
  // 不要因 signComp 已就绪就提前返回：四头签名必须拿到 unifiedComp
  ensureFromMtop();
  if (C.unifiedComp) return true;
  try {
    var SGM = Java.use('com.alibaba.wireless.security.open.SecurityGuardManager');
    var ctx = getContext();
    var mgr = ctx ? SGM.getInstance(ctx) : SGM.getInstance(Java.use('android.app.ActivityThread').currentApplication());
    if (!mgr) return false;
    C.mgr = mgr;
    try {
      var USC = Java.use('com.alibaba.wireless.security.open.middletier.IUnifiedSecurityComponent');
      var raw = mgr.getInterface(USC.class);
      if (raw) C.unifiedComp = Java.cast(raw, USC);
      C.hookStatus.push('unifiedComp: ' + (C.unifiedComp ? 'ok' : 'null'));
    } catch (e) { C.hookStatus.push('unifiedComp: ' + e); }
    try {
      C.signComp = mgr.getSecureSignatureComp();
    } catch (e) { C.hookStatus.push('signComp: ' + e); }
    C.ready = !!(C.unifiedComp || C.signComp);
  } catch (e) {
    C.hookStatus.push('ensureComponents: ' + e);
  }
  return C.ready;
}

/** 用 MtopConfig 里的 authCode 初始化 middle-tier 组件（对应 tb/n9f.t） */
function initComponents() {
  if (C.initialized) return true;
  ensureComponents();
  if (!C.unifiedComp && !C.signComp) return false;
  try {
    var cfg = null;
    Java.choose('mtopsdk.mtop.global.MtopConfig', {
      onMatch: function (c) { if (!cfg) { cfg = c; return 'stop'; } },
      onComplete: function () {}
    });
    var auth = '';
    if (cfg) {
      try { auth = safeStr(cfg.wuaAuthCode.value); } catch (e) {}
      if (!auth) { try { auth = safeStr(cfg.authCode.value); } catch (e) {} }
    }
    if (!auth) auth = C.authCode || '';
    C.authCode = auth;

    var HM = Java.use('java.util.HashMap');
    if (C.unifiedComp) {
      try {
        var m1 = HM.$new();
        m1.put('authCode', auth);
        C.unifiedComp.init(m1);
        C.hookStatus.push('unifiedInit: ok');
      } catch (e) { C.hookStatus.push('unifiedInit: ' + e); }
    }
    if (C.mgr) {
      try {
        var GC = Java.use('com.alibaba.wireless.security.open.middletier.IMiddleTierGenericComponent');
        var raw = C.mgr.getInterface(GC.class);
        if (raw) {
          var gen = Java.cast(raw, GC);
          var m2 = HM.$new();
          m2.put('auth_code', auth);
          gen.init(m2);
          C.hookStatus.push('genericInit: ok');
        }
      } catch (e) { C.hookStatus.push('genericInit: ' + e); }
    }
    C.initialized = true;
  } catch (e) { C.hookStatus.push('initComponents: ' + e); }
  return C.initialized;
}

/** 从 70102 INPUT 解析真机设备身份（字段索引见 SignContext.buildInput） */
function parseInputDevice(input) {
  if (!input) return;
  var f = input.split('&');
  if (f.length < 15) return;
  C.device.utdid = f[0] || C.device.utdid;
  C.device.uid = f[1] || C.device.uid;
  C.device.appKey = f[3] || C.device.appKey;
  C.device.ttid = f[9] || C.device.ttid;
  C.device.deviceId = f[10] || C.device.deviceId;
  C.device.lat = f[11] || C.device.lat;
  C.device.lng = f[12] || C.device.lng;
  C.device.extdata = f[13] || C.device.extdata;
  C.device.xFeatures = f[14] || C.device.xFeatures;
}

/** 构造 getSecurityFactors 入参：优先复用真机模板，仅替换本次请求相关字段 */
function newRequestId() {
  try { return safeStr(java.util.UUID.randomUUID()); } catch (e) {
    return 'rpc-' + Date.now() + '-' + Math.floor(Math.random() * 100000);
  }
}

function buildFactorsMap(input, appKey, api) {
  var map = null;
  if (C.factorTemplate) map = cloneMap(C.factorTemplate);
  if (!map) {
    var HM = Java.use('java.util.HashMap');
    map = HM.$new();
    map.put('appkey', appKey);
    map.put('data', input);
    map.put('useWua', Java.use('java.lang.Boolean').valueOf(true));
    map.put('env', Java.use('java.lang.Integer').valueOf(0));
    map.put('authCode', C.authCode || '');
    map.put('extendParas', HM.$new());
    map.put('requestId', newRequestId());
    map.put('api', api || '');
    map.put('mtopBusiness', '');
  } else {
    map.put('appkey', appKey);
    map.put('data', input);
    map.put('useWua', Java.use('java.lang.Boolean').valueOf(true));
    map.put('api', api || '');
    map.put('requestId', newRequestId());
  }
  return map;
}

var java = { util: {} };
function initJavaRefs() {
  try { java.util.UUID = Java.use('java.util.UUID'); } catch (e) {}
}

/** 真机四头：IUnifiedSecurityComponent.getSecurityFactors */
function doSign(payload) {
  initComponents();
  if (!C.unifiedComp) return JSON.stringify({ error: 'unifiedSecurityComponent 不可用: ' + C.hookStatus.join(' | ') });

  var input = payload.input || '';
  var appKey = payload.appKey || C.appKey;
  var api = payload.api || '';
  if (!input) return JSON.stringify({ error: 'input 为空' });

  var map = buildFactorsMap(input, appKey, api);
  var headers = {};
  try {
    var ret = C.unifiedComp.getSecurityFactors(map);
    headers = mapToObject(ret);
    if (payload.debug) headers['_factorInputKeys'] = Object.keys(mapToObject(map)).join(',');
  } catch (e) {
    return JSON.stringify({ error: 'getSecurityFactors 失败: ' + errDetail(e), fallback: 'legacy' });
  }
  headers['_source'] = 'frida-real-device';
  headers['_rpc'] = 'signRequest';
  headers['_inputLen'] = String(input.length);
  return JSON.stringify(headers);
}

/** 老协议单串：ISecureSignatureComponent.signRequest(ctx, authCode) */
function doSignLegacy(payload) {
  initComponents();
  if (!C.signComp) return JSON.stringify({ error: 'secureSignatureComponent 不可用: ' + C.hookStatus.join(' | ') });

  var input = payload.input || '';
  var appKey = payload.appKey || C.appKey;
  if (!input) return JSON.stringify({ error: 'input 为空' });

  try {
    var Pctx = Java.use('com.alibaba.wireless.security.open.SecurityGuardParamContext');
    var HM = Java.use('java.util.HashMap');
    var ctx = Pctx.$new();
    ctx.appKey.value = appKey;
    ctx.requestType.value = 3;   // tb/n9f.l: const/4 v1, 0x3
    var m = HM.$new();
    m.put('INPUT', input);
    ctx.paramMap.value = m;
    var ret = C.signComp.signRequest(ctx, C.authCode || '');
    return JSON.stringify({ sign: safeStr(ret), _source: 'frida-real-device', _rpc: 'signRequest-legacy' });
  } catch (e) {
    return JSON.stringify({ error: 'signRequest 失败: ' + errDetail(e) });
  }
}

/** 抓真机模板：getSecurityFactors 入参快照（不影响原调用） */
function installFactorsHook() {
  try {
    var USC = Java.use('com.alibaba.wireless.security.open.middletier.IUnifiedSecurityComponent');
    USC.getSecurityFactors.overload('java.util.HashMap').implementation = function (map) {
      if (!C.factorTemplate) {
        C.factorTemplate = cloneMap(map);
        log('captured getSecurityFactors template, keys=' + Object.keys(mapToObject(map)).join(','));
      }
      return this.getSecurityFactors(map);
    };
    C.hookStatus.push('factorsHook: interface');
    return;
  } catch (e) { C.hookStatus.push('factorsHook interface: ' + e); }

  try {
    Java.enumerateLoadedClassesSync().forEach(function (name) {
      if (name.indexOf('UnifiedSecurityComponent') < 0 && name.indexOf('middletier') < 0) return;
      if (name.indexOf('$') > 0) return;
      try {
        var K = Java.use(name);
        if (!K.getSecurityFactors) return;
        K.getSecurityFactors.overloads.forEach(function (ov) {
          ov.implementation = function (map) {
            if (!C.factorTemplate && map && map.size && map.size() > 0) {
              C.factorTemplate = cloneMap(map);
              log('captured getSecurityFactors template from ' + name);
            }
            return ov.apply(this, arguments);
          };
        });
        C.hookStatus.push('factorsHook: ' + name);
      } catch (e) {}
    });
  } catch (e) { C.hookStatus.push('factorsHook enumerate: ' + e); }
}

/** 抓 70102 INPUT（JNICLibrary 可能延后加载，懒重试） */
var sdkHookRetry = 0;
function installSdkSignHook() {
  try {
    var fac = factoryFor('com.taobao.wireless.security.sdk.SecurityGuardManager');
    if (!fac) throw new Error('SDK SecurityGuard 未加载');
    var SC = fac.use('com.taobao.wireless.security.sdk.securesignature.ISecureSignatureComponent');
    SC.signRequest.overload('com.taobao.wireless.security.sdk.SecurityGuardParamContext').implementation =
      function (ctx) {
        var ret = this.signRequest(ctx);
        try {
          C.sdkSign = {
            appKey: safeStr(ctx.appKey.value),
            requestType: ctx.requestType.value,
            params: mapToObject(ctx.paramMap.value),
            result: safeStr(ret)
          };
        } catch (e) { C.sdkSign = { error: String(e) }; }
        return ret;
      };
    C.hookStatus.push('sdkSignHook: ok');
  } catch (e) {
    C.hookStatus.push('sdkSignHook pending: ' + e);
    if (sdkHookRetry++ < 4) setTimeout(function () { Java.perform(installSdkSignHook); }, 2000);
  }
}

var jnicRetry = 0;
function install70102Hook() {
  try {
    var fac = factoryFor('com.taobao.wireless.security.adapter.JNICLibrary');
    if (!fac) throw new Error('未找到 JNICLibrary 的 ClassLoader');
    var JC = fac.use('com.taobao.wireless.security.adapter.JNICLibrary');
    JC.doCommandNative.implementation = function (cmd, args) {
      var ret = this.doCommandNative(cmd, args);
      if (!C.jnicLog) C.jnicLog = [];
      if (C.jnicLog.length < 60) {
        var brief = { cmd: cmd };
        try {
          brief.a0 = safeStr(args && args[0]).substring(0, 120);
          brief.a1 = safeStr(args && args[1]).substring(0, 240);
          brief.n = args ? args.length : 0;
        } catch (e) {}
        brief.ret = safeStr(ret).substring(0, 120);
        C.jnicLog.push(brief);
      }
      if (cmd === 70102) {
        C.jnicInstance = this;
        C.jnicArgs = [];
        try {
          for (var i = 0; i < args.length; i++) {
            C.jnicArgs.push(safeStr(args[i]).substring(0, 2000));
          }
        } catch (e) {}
        try { C.jnicRet = mapToObject(ret); } catch (e) { C.jnicRet = { raw: safeStr(ret) }; }
        try {
          var s = safeStr(args[1]);
          if (s.indexOf('&') > 0) { C.lastInput = s; parseInputDevice(s); }
        } catch (e) {}
      }
      return ret;
    };
    C.hookStatus.push('jnic70102Hook: ok');
  } catch (e) {
    C.hookStatus.push('jnic70102Hook pending: ' + e);
    if (jnicRetry++ < 4) setTimeout(function () { Java.perform(install70102Hook); }, 2000);
  }
}

/** 抓 buildParams 里的 umt / appKey / ttid 等公共参数 */
function installBuildParamsHook() {
  try {
    var IPB = Java.use('mtopsdk.mtop.protocol.builder.impl.InnerProtocolParamBuilderImpl');
    IPB.buildParams.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var out = ov.apply(this, arguments);
        try {
          // arguments[0] = tb/w4j（完整请求上下文），this = InnerProtocolParamBuilderImpl
          // 保存现场实例，供 signByMtop 复用真机 MtopRequest/Mtop 重新签名。
          if (arguments.length > 0 && arguments[0]) C.requestCtx = arguments[0];
          C.paramBuilder = this;
          var p = mapToObject(out);
          C.lastBuildParamsOut = p;   // 完整返回 Map（诊断四头来源）
          ['umt', 'appKey', 'ttid', 'utdid', 'deviceId', 'sid', 'x-app-ver'].forEach(function (k) {
            if (p[k]) C.device[k] = p[k];
          });
          // 直接快照真机本次请求产出的四头（最保真，无需重新签名）。
          var heads = {};
          ['x-sign', 'x-mini-wua', 'x-sgext', 'x-umt', 'x-gst', 'x-utdid', 'x-devid', 'x-sid',
           'sign', 't', 'appKey', 'api', 'v', 'data', 'umt'].forEach(function (k) {
            if (p[k] !== undefined && p[k] !== null && p[k] !== '') heads[k] = p[k];
          });
          if (heads['x-sign'] || heads['sign']) {
            C.lastRealHeads = heads;
            try { C.lastRealHeadsTime = Date.now(); } catch (e) {}
          }
          // dump w4j 的 Map 字段（i/m 很可能承载最终 header）
          try {
            var w4j = arguments[0];
            C.w4jMaps = {};
            ['i', 'm'].forEach(function (fld) {
              try {
                var mv = w4j[fld].value;
                if (mv) C.w4jMaps[fld] = mapToObject(mv);
              } catch (e) {}
            });
          } catch (e) {}
        } catch (e) {}
        return out;
      };
    });
    C.hookStatus.push('buildParamsHook: ok');
  } catch (e) { C.hookStatus.push('buildParamsHook: ' + e); }
}

/** 网络层抓真实发出的 MTOP 请求头（x-sign/x-mini-wua/x-sgext/x-umt 的 ground truth） */
function installNetworkHeaderHook() {
  var WANT = ['x-sign', 'x-mini-wua', 'x-sgext', 'x-umt', 'x-gst', 'x-sid', 'x-utdid', 'x-devid',
              'sign', 'wua', 't', 'appKey', 'api', 'v', 'data', 'umt', 'x-app-ver', 'ttid'];
  function saveHeaders(url, headers) {
    try {
      var u = String(url);
      // 诊断：记录所有 URL（不过滤），确认请求走的网络栈
      if (!C.netUrlLog) C.netUrlLog = [];
      if (C.netUrlLog.length < 30) {
        var hc = 0;
        try { hc = headers && headers.size ? headers.size() : Object.keys(headers || {}).length; } catch (e) {}
        C.netUrlLog.push(u.substring(0, 180) + ' [headers=' + hc + ']');
      }
      if (u.indexOf('mtop') < 0 && u.indexOf('/gw/') < 0 && u.indexOf('/h5/') < 0) return;
      var heads = {};
      WANT.forEach(function (k) {
        try {
          var v = headers[k] !== undefined ? headers[k] : (headers.get ? headers.get(k) : null);
          if (v !== null && v !== undefined && String(v) !== '') heads[k] = String(v);
        } catch (e) {}
      });
      if (heads['x-sign'] || heads['x-mini-wua'] || heads['sign']) {
        C.netHeaders = heads;
        C.netUrl = u.length > 500 ? u.substring(0, 500) : u;
        C.netHeaderCount = (C.netHeaderCount || 0) + 1;
      }
    } catch (e) {}
  }
  // OkHttp: Request.Builder.build() -> Request
  try {
    var RB = factoryFor('okhttp3.Request$Builder');
    if (RB) {
      var OkRB = RB.use('okhttp3.Request$Builder');
      OkRB.build.implementation = function () {
        var req = this.build();
        try {
          var hs = req.headers();
          var obj = {};
          var names = hs.names();
          for (var i = 0; i < names.size(); i++) {
            var k = names.get(i);
            obj[k] = hs.get(k);
          }
          saveHeaders(req.url(), obj);
        } catch (e) {}
        return req;
      };
      C.hookStatus.push('netOkHttpHook: ok');
    }
  } catch (e) { C.hookStatus.push('netOkHttpHook: ' + e); }
  // HttpURLConnection.setRequestProperty: 抓所有 x-* header（最终发出的真实头，最权威）
  try {
    var HUC = Java.use('java.net.HttpURLConnection');
    HUC.setRequestProperty.implementation = function (k, v) {
      try {
        var key = String(k);
        if (key.indexOf('x-') === 0 || key.indexOf('m-') === 0 || key === 'sign' ||
            key === 'Cookie' || key === 'User-Agent' || key === 'wua') {
          if (!C.headerCapture) C.headerCapture = {};
          C.headerCapture[key] = String(v);
          C.headerCaptureCount = (C.headerCaptureCount || 0) + 1;
        }
      } catch (e) {}
      return this.setRequestProperty(k, v);
    };
    C.hookStatus.push('headerCaptureHook: ok');
  } catch (e) { C.hookStatus.push('headerCaptureHook: ' + e); }
  // ANetwork: RequestImpl.getUrlString() + getHeaders()
  try {
    var AF = factoryFor('anetwork.channel.entity.RequestImpl');
    if (AF) {
      var RI = AF.use('anetwork.channel.entity.RequestImpl');
      RI.getUrlString.implementation = function () {
        var url = this.getUrlString();
        try {
          var hs = this.getHeaders();
          var obj = {};
          if (hs) {
            for (var i = 0; i < hs.size(); i++) {
              var hd = hs.get(i);
              obj[hd.getName()] = hd.getValue();
            }
          }
          saveHeaders(url, obj);
        } catch (e) {}
        return url;
      };
      C.hookStatus.push('netANetworkHook: ok');
    }
  } catch (e) { C.hookStatus.push('netANetworkHook: ' + e); }
}

function setStringField(obj, name, value) {
  try {
    obj[name].value = Java.use('java.lang.String').$new(String(value));
    return true;
  } catch (e) {}
  try {
    var Field = Java.use('java.lang.reflect.Field');
    var f = Java.cast(obj.getClass().getDeclaredField(name), Field);
    f.setAccessible(true);
    f.set(obj, Java.use('java.lang.String').$new(String(value)));
    return true;
  } catch (e) {}
  return false;
}

/** 复用真机已初始化 MtopRequest/Mtop 上下文，调用 App 自己的 buildParams 产签名头。 */
function signByMtop(payload) {
  var ctx = null;
  var builder = null;
  Java.choose('tb/w4j', {
    onMatch: function (inst) { if (!ctx) { ctx = inst; return 'stop'; } },
    onComplete: function () {}
  });
  Java.choose('mtopsdk.mtop.protocol.builder.impl.InnerProtocolParamBuilderImpl', {
    onMatch: function (inst) { if (!builder) { builder = inst; return 'stop'; } },
    onComplete: function () {}
  });
  if (ctx) C.requestCtx = ctx;
  if (builder) C.paramBuilder = builder;
  if (!ctx) ctx = C.requestCtx;
  if (!builder) {
    try { builder = Java.use('mtopsdk.mtop.protocol.builder.impl.InnerProtocolParamBuilderImpl').$new(); }
    catch (e) { builder = C.paramBuilder; }
  }
  if (!ctx || !builder) {
    return JSON.stringify({ error: '尚未捕获真机 Mtop 请求上下文，请先触发一次 App 搜索' });
  }
  try {
    var req = ctx.b.value;
    if (!req) return JSON.stringify({ error: 'MtopRequest 为空' });
    var changed = {
      api: setStringField(req, 'apiName', payload.api || ''),
      version: setStringField(req, 'version', payload.version || '1.0'),
      data: setStringField(req, 'data', payload.data || '{}')
    };
    var outMap = builder.buildParams(ctx);
    var out = mapToObject(outMap);
    out._changed = changed;
    out._source = 'frida-real-device-buildParams';
    out._api = payload.api || '';
    return JSON.stringify(out);
  } catch (e) {
    return JSON.stringify({ error: errDetail(e) });
  }
}

function nativeInvoke70102(args) {
  if (!C.native70102.attached || !C.native70102.fnPtr) {
    return JSON.stringify({ error: 'native doCommandNative 未捕获，请使用 FRIDA_SPAWN=1 启动桥接' });
  }
  var env = Java.vm.getEnv().handle;
  var cls = C.native70102.classGlobal;
  if (!cls || cls.isNull()) return JSON.stringify({ error: 'JNICLibrary class global ref 未捕获' });

  var findClass = nJniFn(env, 6, 'pointer', ['pointer', 'pointer']);
  var newString = nJniFn(env, 167, 'pointer', ['pointer', 'pointer']);
  var newArray = nJniFn(env, 172, 'pointer', ['pointer', 'int32', 'pointer', 'pointer']);
  var setElem = nJniFn(env, 174, 'void', ['pointer', 'pointer', 'int32', 'pointer']);

  var objCls = findClass(env, Memory.allocUtf8String('java/lang/Object'));
  if (!objCls || objCls.isNull()) return JSON.stringify({ error: 'FindClass(java/lang/Object) 失败' });
  var arr = newArray(env, args.length, objCls, ptr(0));
  if (!arr || arr.isNull()) return JSON.stringify({ error: 'NewObjectArray 失败' });

  for (var i = 0; i < args.length; i++) {
    var v = args[i];
    if (v === null || v === undefined) continue; // 新数组元素本来就是 null
    var s = newString(env, Memory.allocUtf8String(String(v)));
    if (!s || s.isNull()) return JSON.stringify({ error: 'NewStringUTF 失败 at ' + i });
    setElem(env, arr, i, s);
  }

  var fn = new NativeFunction(ptr(C.native70102.fnPtr), 'pointer',
    ['pointer', 'pointer', 'int32', 'pointer']);
  var ret = fn(env, cls, 70102, arr);
  var out = { rawRet: nJobjectToString(env, ret) };
  try {
    if (ret && !ret.isNull()) {
      var map = mapToObject(Java.cast(ret, Java.use('java.util.Map')));
      Object.keys(map).forEach(function (k) { out[k] = map[k]; });
    }
  } catch (e) { out._mapError = String(e); }
  out._source = 'frida-native-doCommandNative-70102';
  return JSON.stringify(out);
}

function invokeJnic(payload) {
  try {
    var fac = factoryFor('com.taobao.wireless.security.adapter.JNICLibrary');
    if (!fac) throw new Error('未找到 JNICLibrary ClassLoader');
    var JC = fac.use('com.taobao.wireless.security.adapter.JNICLibrary');
    var args = payload.args || [];
    var vals = [];
    for (var i = 0; i < args.length; i++) {
      vals.push(args[i] === null || args[i] === undefined ? null : String(args[i]));
    }
    // 用反射构造 Object[]，避免不同 frida-java-bridge 版本 Java.array 的转换差异。
    // 必须与 JNICLibrary 使用同一个 ClassFactory，否则跨 VM 包装会报 $borrowClassHandle。
    var ArrayCls = fac.use('java.lang.reflect.Array');
    var arr = ArrayCls.newInstance(fac.use('java.lang.Object').class, vals.length);
    for (var j = 0; j < vals.length; j++) arr[j] = vals[j];
    var cmd = parseInt(payload.cmd || '70102', 10);
    var ret = null;
    var errs = [];
    JC.doCommandNative.overloads.forEach(function (ov) {
      if (ret !== null || errs.length >= 3) return;
      try { ret = ov(cmd, arr); } catch (e) { errs.push(String(ov) + ' -> ' + errDetail(e)); }
    });
    if (ret === null && errs.length) throw new Error(errs.join(' | '));
    var out = {};
    try {
      if (ret && ret.getClass && String(ret.getClass().getName()).indexOf('HashMap') >= 0) {
        out = mapToObject(ret);
      } else {
        out.raw = safeStr(ret);
      }
    } catch (e) { out.raw = safeStr(ret); }
    out._source = 'frida-JNICLibrary.doCommandNative';
    out._cmd = cmd;
    return JSON.stringify(out);
  } catch (e) {
    return JSON.stringify({ error: errDetail(e) });
  }
}

rpc.exports = {
  /**
   * 免登录原生搜索：用 App 自己的 Mtop 实例 + MtopBuilder.syncRequest() 发请求。
   * 请求 100% 走 anetwork 原生协议栈（自动签名 + 原生请求形态），
   * 绕开手工 HTTP form 被 bixi 标 wh_ttid=pc 的 web 风控。
   * 游客态（不注入登录 cookie），风控允许时可出真实数据。
   *
   * 关键修复：MtopBuilder.$new 必须 overload 到 MtopRequest 构造，否则匹配
   * Object 重载 -> inputDoToMtopRequest 错误转换 -> apiName=null -> INIT_ERROR。
   * 图片走 POST 避免 base64 塞 URL 触发 414。
   *
   * payload: {api, version, data, ttid, method:'POST'|'GET', headers:{}}
   */
  nativeSearch: function (payloadJson) {
    var out = {error: null, step: 'start'};
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) {
      return JSON.stringify({error: 'bad payload: ' + e});
    }
    Java.perform(function () {
      try {
        // 1) 拿 App 的 Mtop 实例（优先存活 context 的 builder.mtopInstance）
        var Mtop = Java.use('mtopsdk.mtop.intf.Mtop');
        var mtop = null, iid = null;
        try {
          Java.choose('tb/w4j', {
            onMatch: function (inst) {
              if (mtop) return;
              try {
                var o = inst.o.value;
                if (o !== null) {
                  var mi = o.mtopInstance.value;
                  if (mi !== null) {
                    mtop = mi;
                    try { iid = String(mi.getInstanceId()); } catch (e) {}
                    return 'stop';
                  }
                }
              } catch (e) {}
            }, onComplete: function () {}
          });
        } catch (e) {}
        if (!mtop) {
          var cands = ['', 'INNER', 'taobao', '21646297'];
          for (var i = 0; i < cands.length; i++) {
            try { mtop = Mtop.getInstance(cands[i]); if (mtop) { iid = cands[i]; break; } } catch (e) {}
          }
        }
        if (!mtop) { out.error = 'no Mtop instance'; return; }
        out.instanceId = iid;

        // 2) 构造合法 MtopRequest
        out.step = 'MtopRequest';
        var MtopRequest = Java.use('mtopsdk.mtop.domain.MtopRequest');
        var mreq = MtopRequest.$new();
        mreq.setApiName(payload.api);
        mreq.setVersion(payload.version || '1.0');
        mreq.setData(payload.data);
        try { mreq.setNeedSession(false); } catch (e) {}
        out.reqApi = String(mreq.getApiName());

        // 3) headers
        out.step = 'headers';
        var HashMap = Java.use('java.util.HashMap');
        var hdr = HashMap.$new();
        var H = payload.headers || {};
        Object.keys(H).forEach(function (k) { hdr.put(k, String(H[k])); });

        // 4) MtopBuilder：显式 MtopRequest 重载 + POST + syncRequest
        out.step = 'builder';
        var MB = Java.use('mtopsdk.mtop.intf.MtopBuilder');
        var ctor = MB.$new.overload('mtopsdk.mtop.intf.Mtop',
                                    'mtopsdk.mtop.domain.MtopRequest', 'java.lang.String');
        var ttid = payload.ttid || '231200@taobao_android_10.69.10';
        var builder = ctor.call(MB, mtop, mreq, ttid);
        builder.headers(hdr);
        if (payload.method === 'POST') {
          var MethodEnum = Java.use('mtopsdk.mtop.domain.MethodEnum');
          builder.reqMethod(MethodEnum.POST.value);
          try { builder.allowSwitchToPOST(true); } catch (e) {}
        }
        builder.ttid(ttid);

        out.step = 'syncRequest';
        var resp = builder.syncRequest();
        out.step = 'done';
        if (resp === null) { out.error = 'null response'; return; }
        try { out.retCode = String(resp.getRetCode()); } catch (e) {}
        try { out.retMsg = String(resp.getRetMsg()); } catch (e) {}
        try { var rets = resp.getRet(); out.ret = rets ? String(rets.toString()) : null; } catch (e) {}
        try {
          var jo = resp.getDataJsonObject();
          out.data = jo ? String(jo.toString()) : null;
        } catch (e) { out.dataErr = String(e); }
        try { out.raw = String(resp.toString()).substring(0, 800); } catch (e) {}
      } catch (e) { out.error = String(e); out.step = out.step || 'ex'; }
    });
    return JSON.stringify(out);
  },

  jnicSignature: function () {
    var out = [];
    Java.perform(function () {
      try {
        var fac = factoryFor('com.taobao.wireless.security.adapter.JNICLibrary');
        if (!fac) { out.push('class not found'); return; }
        var JC = fac.use('com.taobao.wireless.security.adapter.JNICLibrary');
        JC.doCommandNative.overloads.forEach(function (ov) { out.push(String(ov)); });
      } catch (e) { out.push('err ' + e); }
    });
    return JSON.stringify(out);
  },

  invokeJnic: function (payloadJson) {
    var out = null;
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) {
      return JSON.stringify({ error: 'bad payload: ' + e });
    }
    Java.perform(function () { out = invokeJnic(payload); });
    return out || JSON.stringify({ error: 'Java.perform 未返回结果' });
  },

  debugMtop: function () {
    var out = [];
    Java.perform(function () {
      try {
        var Mtop = Java.use('mtopsdk.mtop.intf.Mtop');
        var instances = Mtop.instanceMap.value;
        if (!instances) { out.push('instanceMap=null'); return; }
        var it = instances.entrySet().iterator();
        while (it.hasNext()) {
          var en = it.next();
          var line = safeStr(en.getKey()) + ' => ';
          var m = en.getValue();
          try {
            var cfg = m.getMtopConfig();
            line += 'cfg=' + (cfg ? safeStr(cfg.getClass().getName()) : 'null');
            if (cfg) {
              try { line += ' sign=' + safeStr(cfg.sign.value.getClass().getName()); }
              catch (e) { line += ' signErr=' + e; }
              try { line += ' appKey=' + safeStr(cfg.appKey.value); } catch (e) {}
            }
          } catch (e) { line += ' err=' + e; }
          out.push(line);
        }
      } catch (e) { out.push('debugMtop err=' + e); }
    });
    return JSON.stringify(out);
  },

  /** SDK 版 ISecureSignatureComponent.signRequest(ctx)（本 APK classes10 实际调用形态） */
  signSdk: function (payloadJson) {
    var out = null;
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) { return JSON.stringify({ error: 'bad payload: ' + e }); }
    Java.perform(function () {
      var step = {};
      try {
        var fac = factoryFor('com.taobao.wireless.security.sdk.SecurityGuardManager');
        if (!fac) throw new Error('未找到 SDK SecurityGuard 的 ClassLoader');
        var Sgm = fac.use('com.taobao.wireless.security.sdk.SecurityGuardManager');
        var ctx = getContext();
        var mgr = Sgm.getInstance(ctx);
        var comp = Java.cast(mgr.getSecureSignatureComp(),
          fac.use('com.taobao.wireless.security.sdk.securesignature.ISecureSignatureComponent'));
        var Pctx = fac.use('com.taobao.wireless.security.sdk.SecurityGuardParamContext');
        var HM = Java.use('java.util.HashMap');
        var input = String(payload.input || '');
        var reqTypes = payload.requestTypes || [3, 7, 1];
        var results = {};
        reqTypes.forEach(function (rt) {
          try {
            var p = Pctx.$new();
            p.appKey.value = String(payload.appKey || '21646297');
            p.requestType.value = rt;
            var m = HM.$new();
            m.put('INPUT', input);
            p.paramMap.value = m;
            results[String(rt)] = safeStr(comp.signRequest(p));
          } catch (e) { results[String(rt)] = 'ERR ' + errDetail(e); }
        });
        step.results = results;
        step._source = 'frida-sdk-signRequest';
        out = JSON.stringify(step);
      } catch (e) { out = JSON.stringify({ error: errDetail(e) }); }
    });
    return out || JSON.stringify({ error: 'Java.perform 未返回结果' });
  },

  native70102: function () {
    return JSON.stringify(C.native70102);
  },

  /** 诊断：网络层 hook 看到的所有 URL */
  netUrlLog: function () {
    return JSON.stringify(C.netUrlLog || []);
  },

  /** 诊断：最近一次 buildParams 返回的完整 Map */
  buildParamsOut: function () {
    return JSON.stringify(C.lastBuildParamsOut || { error: '尚未捕获 buildParams 返回' });
  },

  /** 诊断：w4j 的 Map 字段（i/m，可能承载 header） */
  w4jMaps: function () {
    return JSON.stringify(C.w4jMaps || { error: '尚未捕获 w4j Maps' });
  },

  /** HttpURLConnection 抓到的真实 x-* 请求头（ground truth） */
  headerCapture: function () {
    if (!C.headerCapture) {
      return JSON.stringify({ error: '尚未抓到请求头', count: C.headerCaptureCount || 0 });
    }
    var h = JSON.parse(JSON.stringify(C.headerCapture));
    h._count = C.headerCaptureCount;
    h._source = 'frida-httpurlconnection-header-groundtruth';
    return JSON.stringify(h);
  },

  /** 网络层抓到的真实 MTOP 请求头（四头 ground truth） */
  netHeaders: function () {
    if (!C.netHeaders) {
      return JSON.stringify({ error: '尚未抓到网络层 MTOP 请求头，请先触发一次 App 搜索',
        netHeaderCount: C.netHeaderCount || 0 });
    }
    var h = JSON.parse(JSON.stringify(C.netHeaders));
    h._url = C.netUrl;
    h._count = C.netHeaderCount;
    h._source = 'frida-network-header-groundtruth';
    return JSON.stringify(h);
  },

  /** 最近一次真机 r() 成功产出的四头 */
  successSign: function () {
    if (!C.successHeads) {
      return JSON.stringify({ error: '尚未捕获到 r() 成功产出的四头',
        rCallCount: C.rCallCount || 0, rSuccessCount: C.rSuccessCount || 0 });
    }
    var h = JSON.parse(JSON.stringify(C.successHeads));
    h._api = C.successApi;
    h._useWua = C.successUseWua;
    h._rCallCount = C.rCallCount;
    h._rSuccessCount = C.rSuccessCount;
    h._source = 'frida-real-innerSign.r-success';
    return JSON.stringify(h);
  },

  /** 用真机成功那次的原始入参重放 r()；可覆盖 data/api 重新签名 */
  replaySuccess: function (payloadJson) {
    var out = null;
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) {
      return JSON.stringify({ error: 'bad payload: ' + e });
    }
    Java.perform(function () {
      try {
        if (!C.successRArgs || !C.successRThis) {
          out = JSON.stringify({ error: '没有成功的 r() 入参可供重放，请先触发真机搜索' });
          return;
        }
        var orig = C.successRArgs;
        var HM = Java.use('java.util.HashMap');
        var p1 = orig[0];
        var p2 = orig[1];
        // 可选覆盖字段
        if (payload.data) p1.put('data', String(payload.data));
        if (payload.api) p1.put('api', String(payload.api));
        if (payload.t) p1.put('t', String(payload.t));
        if (payload.v) p1.put('v', String(payload.v));
        var api = payload.api || safeStr(orig[2]);
        var ver = payload.v || safeStr(orig[3]);
        var useWua = payload.useWua === undefined ? true : !!payload.useWua;
        var reqId = payload.requestId || safeStr(orig[5]) || 'rpc_replay';
        var ret = C.successRThis.r(p1, p2, api, ver, useWua, reqId);
        var r = mapToObject(ret);
        r._source = 'frida-real-innerSign.r-replay';
        r._api = api;
        out = JSON.stringify(r);
      } catch (e) {
        out = JSON.stringify({ error: 'replay 失败: ' + errDetail(e) });
      }
    });
    return out || JSON.stringify({ error: 'Java.perform 未返回结果' });
  },

  /** 直接返回最近一次真机 buildParams 产出的四头快照（无需重新签名，保真度最高） */
  realHeads: function () {
    if (!C.lastRealHeads) {
      return JSON.stringify({ error: '尚未捕获真机四头，请先触发一次 App 搜索',
        hasRequestCtx: !!C.requestCtx });
    }
    var h = JSON.parse(JSON.stringify(C.lastRealHeads));
    h._capturedAt = C.lastRealHeadsTime;
    h._source = 'frida-real-device-buildParams-snapshot';
    return JSON.stringify(h);
  },

  signByMtop: function (payloadJson) {
    var out = null;
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) {
      return JSON.stringify({ error: 'bad payload: ' + e });
    }
    Java.perform(function () { out = signByMtop(payload); });
    return out || JSON.stringify({ error: 'Java.perform 未返回结果' });
  },

  nativeSign: function (payloadJson) {
    var out = null;
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) {
      return JSON.stringify({ error: 'bad payload: ' + e });
    }
    Java.perform(function () { out = nativeInvoke70102(payload.args || []); });
    return out || JSON.stringify({ error: 'Java.perform 未返回结果' });
  },

  findJnicClasses: function () {
    var out = [];
    Java.perform(function () {
      try {
        Java.enumerateLoadedClassesSync().forEach(function (name) {
          if (name.indexOf('JNIC') >= 0 || name.indexOf('security.adapter') >= 0
              || name.indexOf('security.sdk') >= 0) {
            var methods = [];
            try {
              Java.use(name).class.getDeclaredMethods().forEach(function (m) {
                if (String(m.getName()).indexOf('doCommand') >= 0
                    || String(m.getName()).indexOf('sign') >= 0) methods.push(String(m));
              });
            } catch (e) {}
            out.push(name + ' :: ' + methods.join(' | '));
          }
        });
      } catch (e) { out.push('err ' + e); }
    });
    return JSON.stringify(out);
  },

  lastCapture: function () {
    return JSON.stringify({ api: C.lastRealApi, args: C.lastRealArgs,
      params: C.lastRealParams, paramsAfter: C.lastRealParamsAfter, result: C.lastRealResult,
      f: C.last_f, g: C.last_g, sdkSign: C.sdkSign, jnicLog: C.jnicLog,
      jnicArgs: C.jnicArgs, jnicRet: C.jnicRet,
      hasJnic: !!C.jnicInstance, hasTemplate: !!C.factorTemplate });
  },

  debugInstances: function () {
    var out = [];
    Java.perform(function () {
      try {
        Java.choose('tb/n9f', {
          onMatch: function (inst) {
            var line = 'n9f: ';
            ['a', 'c', 'e', 'f'].forEach(function (k) {
              try {
                var v = inst[k].value;
                line += k + '=' + (v === null ? 'null' : safeStr(v.getClass().getName())) + ' ';
              } catch (e) { line += k + '=ERR(' + e + ') '; }
            });
            out.push(line);
          },
          onComplete: function () {}
        });
      } catch (e) { out.push('choose n9f err ' + e); }
      try {
        Java.choose('mtopsdk.mtop.global.MtopConfig', {
          onMatch: function (cfg) {
            var line = 'cfg: ';
            ['appKey', 'ttid', 'utdid', 'deviceId', 'wuaAuthCode'].forEach(function (k) {
              try { line += k + '=' + safeStr(cfg[k].value) + ' '; } catch (e) { line += k + '=ERR '; }
            });
            out.push(line);
            return 'stop';
          },
          onComplete: function () {}
        });
      } catch (e) { out.push('choose cfg err ' + e); }
    });
    return JSON.stringify(out);
  },

  status: function () {
    var r = { ready: C.ready, hasUnified: !!C.unifiedComp, hasSign: !!C.signComp,
      hasInnerSign: !!C.innerSign, hasRequestCtx: !!C.requestCtx,
      hasRealHeads: !!C.lastRealHeads, hasSuccessHeads: !!C.successHeads,
      hasNetHeaders: !!C.netHeaders, netHeaderCount: C.netHeaderCount || 0,
      hasHeaderCapture: !!C.headerCapture, headerCaptureCount: C.headerCaptureCount || 0,
      rCallCount: C.rCallCount || 0, rSuccessCount: C.rSuccessCount || 0,
      instanceId: C.instanceId, appKey: C.appKey,
      authCode: C.authCode ? 'present' : '', hasTemplate: !!C.factorTemplate,
      lastInputLen: C.lastInput.length, hooks: C.hookStatus };
    return JSON.stringify(r);
  },

  deviceInfo: function () {
    var out = null;
    Java.perform(function () { out = JSON.stringify(C.device); });
    return out || JSON.stringify(C.device);
  },

  /** 直接调用真机 InnerSignImpl.r(...)：与 App 搜索时走同一入口，内部自行初始化 middle-tier */
  signByInner: function (payloadJson) {
    var out = null;
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) { return JSON.stringify({ error: 'bad payload: ' + e }); }
    Java.perform(function () {
      try {
        ensureComponents();
        if (!C.innerSign) { out = JSON.stringify({ error: 'InnerSignImpl 实例不可用' }); return; }
        var HM = Java.use('java.util.HashMap');
        var p1 = objectToMap(payload.params || {});
        var p2 = objectToMap(payload.extend || {});
        var api = payload.api || safeStr(p1.get('api') || '');
        var ver = payload.version || safeStr(p1.get('v') || '1.0');
        var ret = C.innerSign.r(p1, p2, api, ver, true, payload.requestId || '');
        var r = mapToObject(ret);
        r['_source'] = 'frida-real-innerSign.r';
        r['_api'] = api;
        out = JSON.stringify(r);
      } catch (e) {
        out = JSON.stringify({ error: 'InnerSignImpl.r 失败: ' + e });
      }
    });
    return out || JSON.stringify({ error: 'Java.perform 未返回结果' });
  },

  /** 精确复刻 tb/n9f.r 的四头组装：f() 生成 INPUT -> getSecurityFactors() */
  signExact: function (payloadJson) {
    var out = null;
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) { return JSON.stringify({ error: 'bad payload: ' + e }); }
    Java.perform(function () {
      var step = {};
      try {
        ensureComponents();
        if (!C.innerSign) throw new Error('InnerSignImpl 不可用');
        var HM = Java.use('java.util.HashMap');
        var p1 = objectToMap(payload.params || {});
        var p2 = objectToMap(payload.extend || {});
        var appKey = String(payload.appKey || p1.get('appKey') || '21646297');

        // 1) 真机自己拼 INPUT（tb/n9f.f）
        var factors = C.innerSign.f(p1, appKey, true);
        step.factors = mapToObject(factors);
        var input = safeStr(factors.get('INPUT'));
        step.input = input;
        if (!input) throw new Error('INPUT 为空');

        // 2) 真机 getSecurityFactors（tb/n9f.r 后半段）
        if (!C.unifiedComp) throw new Error('unifiedComp 不可用: ' + C.hookStatus.join(' | '));
        var auth = '';
        try { auth = safeStr(C.innerSign.a()); } catch (e) { step.authErr = String(e); }
        if (!auth) auth = C.authCode || '';
        var env = 0;
        try { env = C.innerSign.m(); } catch (e) {}
        var m = HM.$new();
        m.put('appkey', appKey);
        m.put('data', input);
        m.put('useWua', Java.use('java.lang.Boolean').valueOf(true));
        m.put('env', Java.use('java.lang.Integer').valueOf(env));
        m.put('authCode', auth);
        m.put('extendParas', p2);
        m.put('requestId', String(payload.requestId || ''));
        m.put('api', safeStr(p1.get('api')));
        m.put('mtopBusiness', safeStr(p1.get('mtopBusiness')));
        var ret = C.unifiedComp.getSecurityFactors(m);
        step.headers = mapToObject(ret);
        step._source = 'frida-real-device-exact';
        out = JSON.stringify(step);
      } catch (e) {
        step.error = errDetail(e);
        out = JSON.stringify(step);
      }
    });
    return out || JSON.stringify({ error: 'Java.perform 未返回结果' });
  },

  /** 诊断：直接调用 InnerSignImpl.l(s1,s2) 老协议签名 */
  signLegacyByInner: function (payloadJson) {
    var out = null;
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) { return JSON.stringify({ error: 'bad payload: ' + e }); }
    Java.perform(function () {
      try {
        ensureComponents();
        if (!C.innerSign) { out = JSON.stringify({ error: 'InnerSignImpl 实例不可用' }); return; }
        var ret = C.innerSign.l(String(payload.s1 || ''), String(payload.s2 || ''));
        out = JSON.stringify({ sign: safeStr(ret), _source: 'frida-innerSign.l' });
      } catch (e) { out = JSON.stringify({ error: 'innerSign.l 失败: ' + errDetail(e) }); }
    });
    return out || JSON.stringify({ error: 'Java.perform 未返回结果' });
  },

  signRequest: function (payloadJson) {
    var out = null;
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) { return JSON.stringify({ error: 'bad payload: ' + e }); }
    Java.perform(function () {
      initJavaRefs();
      out = doSign(payload);
    });
    return out || JSON.stringify({ error: 'Java.perform 未返回结果' });
  },

  signLegacy: function (payloadJson) {
    var out = null;
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) { return JSON.stringify({ error: 'bad payload: ' + e }); }
    Java.perform(function () { out = doSignLegacy(payload); });
    return out || JSON.stringify({ error: 'Java.perform 未返回结果' });
  }
};

Java.perform(function () {
  log('loading real-device sign RPC');
  installFactorsHook();
  try {
    var N9 = Java.use('tb/n9f');
    N9.r.overloads.forEach(function (ov) {
      ov.implementation = function () {
        C.innerSign = this;              // 捕获 App 正在使用的实例，避免 Java.choose 拿到旧实例
        try { if (this.f.value) C.unifiedComp = this.f.value; } catch (e) {}
        var args = [];
        for (var i = 0; i < arguments.length; i++) {
          var a = arguments[i];
          var cls = '';
          try { cls = a.getClass().getName(); } catch (e) {}
          args.push(i + ':[' + cls + ']' + safeStr(a).substring(0, 120));
        }
        C.lastRealArgs = args;
        C.lastRealApi = safeStr(arguments[2]);
        try { C.lastRealParams = mapToObject(arguments[0]); } catch (e) { C.lastRealParams = { _error: String(e) }; }
        C.rCallCount = (C.rCallCount || 0) + 1;
        // 保存本次原始 Java 参数对象引用（供 RPC 原样重放，保留真机 22 段 INPUT 与设备态）
        C.lastRArgs = arguments;
        C.lastRThis = this;
        var useWua = false;
        try { useWua = arguments[4] === true || String(arguments[4]) === 'true'; } catch (e) {}
        var ret = ov.apply(this, arguments);
        var retObj = null;
        try { retObj = mapToObject(ret); } catch (e) { retObj = { _error: String(e) }; }
        C.lastRealResult = retObj;
        try { C.lastRealParamsAfter = mapToObject(arguments[0]); } catch (e) {}
        // 记录成功产出四头的一次（x-mini-wua / x-sgext / x-sign / wua / sign）
        if (retObj && !retObj._error) {
          var keys = Object.keys(retObj);
          var headKeys = keys.filter(function (k) {
            return /^(x-mini-wua|x-sgext|x-sign|x-umt|x-gst|wua|sign)$/.test(k);
          });
          if (headKeys.length) {
            C.successHeads = retObj;
            C.successApi = safeStr(arguments[2]);
            C.successUseWua = useWua;
            C.successRArgs = arguments;   // 成功那次的完整入参对象
            C.successRThis = this;
            C.rSuccessCount = (C.rSuccessCount || 0) + 1;
          }
        }
        return ret;
      };
    });
    ['f', 'g'].forEach(function (name) {
      try {
        N9[name].overloads.forEach(function (ov) {
          ov.implementation = function () {
            var ret = ov.apply(this, arguments);
            C['last_' + name] = { args: arguments.length, ret: mapToObject(ret) };
            return ret;
          };
        });
        C.hookStatus.push('innerSign.' + name + ': ok');
      } catch (e) { C.hookStatus.push('innerSign.' + name + ': ' + e); }
    });
    C.hookStatus.push('innerSign.r: ok');
  } catch (e) { C.hookStatus.push('innerSign.r: ' + e); }
  installSdkSignHook();
  // install70102Hook() / installNative70102Dump() 已禁用：
  // 它们对高频 doCommandNative 做 JNI dump，会触发 JNI 异常并导致淘宝进程重启，
  // 且对 buildParams 主路径无用。真机四头改由 buildParams hook 直接快照。
  installBuildParamsHook();
  installNetworkHeaderHook();
  ensureComponents();
  log('ready=' + C.ready + ' hooks=' + C.hookStatus.join(' | '));
});
