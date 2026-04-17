cordova.define('cordova/plugin_list', function(require, exports, module) {
  module.exports = [
    {
      "id": "cordova-plugin-aran-rasp.RASP",
      "file": "plugins/cordova-plugin-aran-rasp/www/rasp.js",
      "pluginId": "cordova-plugin-aran-rasp",
      "clobbers": [
        "AranRASP"
      ]
    }
  ];
  module.exports.metadata = {
    "cordova-plugin-aran-rasp": "1.0.0"
  };
});