/*
 * 诊断 system_server 内 PackageManagerService 状态：
 *  - 检查 mPackages 是否含 com.taobao.taobao
 *  - 检查 mSettings.mPackages (PackageSetting) 是否含淘宝
 *  - 列出所有 /data/app 相关 package
 * attach 到 system_server 进程运行。
 */
'use strict';

function dumpMapKeys(label, mapObj) {
  try {
    var keys = mapObj.keySet().toArray();
    console.log(label + ' count=' + keys.length);
    for (var i = 0; i < keys.length; i++) {
      var k = String(keys[i]);
      if (k.indexOf('taobao') >= 0 || k.indexOf('data/app') >= 0) {
        console.log('  >>> ' + k);
      }
    }
  } catch (e) {
    console.log(label + ' ERR ' + e);
  }
}

Java.perform(function () {
  console.log('\n===== diag_pms loaded =====');

  // 1) 通过 ActivityThread 拿 PIPackageManager (PMS 的 Binder)
  var at = Java.use('android.app.ActivityThread');
  var app = at.currentApplication();
  var pm = app.getPackageManager();
  console.log('PM = ' + pm);

  // 2) 反射拿 PMS 内部 mPackages / mSettings
  try {
    var pmClass = Java.use('android.app.ApplicationPackageManager');
    var mPMField = pmClass.getDeclaredField('mPM');
    mPMField.setAccessible(true);
    var pmsBinder = mPMField.get(pm);
    console.log('PMS binder = ' + pmsBinder);

    // PMS 实现类
    var pmsClass = Java.use('com.android.server.pm.PackageManagerService');
    var mPackagesField = pmsClass.getDeclaredField('mPackages');
    mPackagesField.setAccessible(true);
    var mPackages = mPackagesField.get(pmsBinder);
    dumpMapKeys('mPackages', mPackages);

    // 直接 get
    var HM = Java.use('java.util.HashMap');
    var taobao = mPackages.get('com.taobao.taobao');
    console.log('mPackages.get(com.taobao.taobao) = ' + taobao);

    // mSettings
    var mSettingsField = pmsClass.getDeclaredField('mSettings');
    mSettingsField.setAccessible(true);
    var settings = mSettingsField.get(pmsBinder);
    console.log('settings = ' + settings);
    var Settings = Java.use('com.android.server.pm.Settings');
    var mPackagesSField = Settings.getDeclaredField('mPackages');
    mPackagesSField.setAccessible(true);
    var sPackages = mPackagesSField.get(settings);
    dumpMapKeys('Settings.mPackages', sPackages);
    var tbSetting = sPackages.get('com.taobao.taobao');
    console.log('Settings.mPackages.get(taobao) = ' + tbSetting);

  } catch (e) {
    console.log('REFLECT ERR: ' + e);
  }

  console.log('===== diag done =====\n');
});
