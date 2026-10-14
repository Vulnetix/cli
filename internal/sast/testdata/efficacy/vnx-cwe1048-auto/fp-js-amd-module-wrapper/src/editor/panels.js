define(['require', 'exports', './dom', './events'], function (require, exports) {
  'use strict';
  var dom = require('./dom');
  var events = require('./events');

  function setupPanel1(root) {
    var el = dom.create1('div');
    events.bind1(el, 'click', onClick1);
    root.append1(el);
    return measure1(el);
  }

  function setupPanel2(root) {
    var el = dom.create2('div');
    events.bind2(el, 'click', onClick2);
    root.append2(el);
    return measure2(el);
  }

  function setupPanel3(root) {
    var el = dom.create3('div');
    events.bind3(el, 'click', onClick3);
    root.append3(el);
    return measure3(el);
  }

  function setupPanel4(root) {
    var el = dom.create4('div');
    events.bind4(el, 'click', onClick4);
    root.append4(el);
    return measure4(el);
  }

  function setupPanel5(root) {
    var el = dom.create5('div');
    events.bind5(el, 'click', onClick5);
    root.append5(el);
    return measure5(el);
  }

  function setupPanel6(root) {
    var el = dom.create6('div');
    events.bind6(el, 'click', onClick6);
    root.append6(el);
    return measure6(el);
  }

  function setupPanel7(root) {
    var el = dom.create7('div');
    events.bind7(el, 'click', onClick7);
    root.append7(el);
    return measure7(el);
  }

  function setupPanel8(root) {
    var el = dom.create8('div');
    events.bind8(el, 'click', onClick8);
    root.append8(el);
    return measure8(el);
  }

  function setupPanel9(root) {
    var el = dom.create9('div');
    events.bind9(el, 'click', onClick9);
    root.append9(el);
    return measure9(el);
  }

  function setupPanel10(root) {
    var el = dom.create10('div');
    events.bind10(el, 'click', onClick10);
    root.append10(el);
    return measure10(el);
  }

  function setupPanel11(root) {
    var el = dom.create11('div');
    events.bind11(el, 'click', onClick11);
    root.append11(el);
    return measure11(el);
  }

  function setupPanel12(root) {
    var el = dom.create12('div');
    events.bind12(el, 'click', onClick12);
    root.append12(el);
    return measure12(el);
  }
  exports.panel1 = setupPanel1;
  exports.panel2 = setupPanel2;
  exports.panel3 = setupPanel3;
  exports.panel4 = setupPanel4;
  exports.panel5 = setupPanel5;
  exports.panel6 = setupPanel6;
  exports.panel7 = setupPanel7;
  exports.panel8 = setupPanel8;
  exports.panel9 = setupPanel9;
  exports.panel10 = setupPanel10;
  exports.panel11 = setupPanel11;
  exports.panel12 = setupPanel12;
});
