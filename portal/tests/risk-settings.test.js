const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const html = fs.readFileSync(path.resolve(__dirname, '../index.html'), 'utf8');
const start = html.indexOf('function updateRiskSignalBadge()');
const end = html.indexOf('function updateHealthDots()', start);

for (const status of ['on', 'off', 'unavailable']) {
  test(`sidebar displays risk signal ${status} separately from backend health`, () => {
    const badge = {};
    const context = {
      state: { riskSettings: { signal: { status, detail: 'Risk status detail' } } },
      document: { getElementById: id => id === 'risk-signal-status' ? badge : null },
    };
    vm.createContext(context);
    vm.runInContext(html.slice(start, end), context);
    context.updateRiskSignalBadge();
    assert.equal(badge.textContent, `PORTAL RISK MONITORING ${status.toUpperCase()}`);
    assert.equal(badge.title, 'Risk status detail');
    assert.equal(badge.className, `sidebar-mode ${status === 'on' ? 'live' : 'degraded'}`);
  });
}

test('both static demo presets explicitly disable local risk prerequisites', () => {
  const context = {};
  vm.createContext(context);
  const begin = html.indexOf('var PRESET_POLICIES =');
  const finish = html.indexOf('\n};', begin) + 3;
  vm.runInContext(html.slice(begin, finish), context);
  for (const preset of ['hardened', 'permissive']) {
    assert.match(context.PRESET_POLICIES[preset], /risk_enforcement: "off"/);
    assert.doesNotMatch(context.PRESET_POLICIES[preset], /blocked_risk_levels/);
  }
});

test('Settings displays loading failures even before a settings response exists', () => {
  const node = () => ({ children: [], style: {}, appendChild(child) { this.children.push(child); } });
  const root = node();
  const context = {
    state: { riskSettings: null, riskSettingsError: 'Stored settings could not be read' },
    document: { createElement: node },
  };
  vm.createContext(context);
  const begin = html.indexOf('function renderSettings(root)');
  const finish = html.indexOf('\n}', begin) + 2;
  vm.runInContext(html.slice(begin, finish), context);
  context.renderSettings(root);
  assert.ok(root.children[0].children.some(child => child.textContent === context.state.riskSettingsError));
});

function renderRiskSettings(role = 'admin') {
  const nodes = [];
  const node = tag => {
    const element = {
      tag, children: [], style: {}, attributes: {},
      appendChild(child) { this.children.push(child); },
      setAttribute(name, value) { this.attributes[name] = value; },
    };
    nodes.push(element);
    return element;
  };
  const root = node('root');
  const context = {
    state: {
      riskSettings: {
        signal: { enabled: true, status: 'unavailable', detail: 'Your tenant is not licensed for this feature.' },
        risk_enforcement_enabled: false, enforcement_control_supported: true,
        entra_runtime_supported: true, risk_cache_seconds: 90,
      },
    },
    currentUser: { role },
    document: { createElement: node, createTextNode: text => ({ textContent: text }) },
  };
  vm.createContext(context);
  const begin = html.indexOf('function renderSettings(root)');
  const finish = html.indexOf('\n}', begin) + 2;
  vm.runInContext(html.slice(begin, finish), context);
  context.renderSettings(root);
  return nodes;
}

test('Settings uses padded product cards, status badges, and accessible switches', () => {
  const nodes = renderRiskSettings();
  assert.equal(nodes.filter(n => n.className === 'card settings-card').length, 2);
  assert.ok(nodes.some(n => n.className === 'badge medium' && n.textContent === 'Unavailable'));
  assert.ok(nodes.some(n => n.className === 'policy-msg warn' && n.textContent === 'Your tenant is not licensed for this feature.'));
  const switches = nodes.filter(n => n.attributes.role === 'switch');
  assert.equal(switches.length, 2);
  assert.ok(switches.every(n => n.attributes.role === 'switch' && n.attributes['aria-label']));
  assert.equal(switches[0].checked, true);
  assert.equal(switches[1].checked, false);
});

test('Settings switches remain disabled for viewers', () => {
  assert.ok(renderRiskSettings('viewer').filter(n => n.tag === 'input').every(n => n.disabled));
});

test('Settings explains runtime enforcement and zero cache lifetime in accessible info buttons', () => {
  const nodes = renderRiskSettings();
  const info = nodes.filter(n => n.className === 'settings-info');
  assert.equal(info.length, 3);
  assert.ok(info.every(n => n.tag === 'button' && n.attributes['aria-describedby']));
  const tips = nodes.filter(n => n.attributes.role === 'tooltip');
  assert.ok(tips.some(n => n.textContent.includes('Portal monitoring may be on or off independently')));
  assert.ok(tips.some(n => n.textContent.includes('Set 0 to check Entra on every call')));
  const input = nodes.find(n => n.id === 'risk-cache-seconds');
  assert.equal(input.value, '90');
  assert.equal(input.min, '0');
});

test('Settings API failures omit downstream response bodies', async () => {
  const context = {
    _accessToken: null,
    fetch: async () => ({
      ok: false, status: 503,
      json: async () => ({
        detail: 'Risk settings could not be read',
        meta: { body: '{"detail":"internal-request-id"}' },
      }),
    }),
  };
  vm.createContext(context);
  vm.runInContext(html.slice(html.indexOf('function api('), html.indexOf('function loadConfig()')), context);
  await assert.rejects(
    context.api('/settings/risk', { hideErrorDetails: true }),
    error => error.message === 'Risk settings could not be read',
  );
});
