const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const portals = [
  {
    file: path.resolve(__dirname, '../index.html'),
    start: '/* ── Auth: MSAL.js integration ── */',
    end: '/* ── Health dots ── */',
    init: 'initAuth()',
    signIn: 'signIn()',
    msal: 'msalInstance',
    splash: 'auth-splash',
  },
  {
    file: path.resolve(__dirname, '../../securityportal-mock/index.html'),
    start: 'var _securityPortalMsal = null;',
    end: '// Wrap fetch calls to add',
    init: 'securityPortalInitAuth()',
    signIn: 'securityPortalSignIn()',
    msal: '_securityPortalMsal',
    splash: 'sp-auth-splash',
  },
];

function createPortal(portal, accounts, redirectResponse = null) {
  const html = fs.readFileSync(portal.file, 'utf8');
  const script = html.slice(html.indexOf(portal.start), html.indexOf(portal.end));
  const elements = new Map();
  const requests = [];
  const msal = {
    handleRedirectPromise: async () => redirectResponse,
    getAllAccounts: () => accounts,
    getActiveAccount: () => msal.activeAccount,
    setActiveAccount: account => { msal.activeAccount = account; },
    acquireTokenSilent: async ({ account }) => {
      requests.push(account);
      return { account, idToken: 'fixture-token', idTokenClaims: account.idTokenClaims };
    },
    loginRedirect: request => { msal.loginRequest = request; },
  };
  const context = {
    msal: { PublicClientApplication: function () { return msal; } },
    document: {
      getElementById: id => {
        if (!elements.has(id)) elements.set(id, { style: {}, textContent: '' });
        return elements.get(id);
      },
      createElement: () => ({ appendChild: () => {}, innerHTML: '' }),
      createTextNode: text => ({ text }),
    },
    window: { location: { origin: 'https://portal.example.test' } },
    fetch: async () => ({
      json: async () => ({
        auth_required: true,
        client_id: 'client-id',
        authority: 'https://login.microsoftonline.com/tenant',
        admin_group_id: 'admin-group',
        viewer_group_id: 'viewer-group',
      }),
    }),
    console,
    setInterval: () => 1,
    clearInterval: () => {},
  };
  vm.createContext(context);
  vm.runInContext(script, context);
  return { context, msal, elements, requests };
}

for (const portal of portals) {
  const name = path.basename(path.dirname(portal.file));
  const account = (username, group) => ({
    username, name: username, idTokenClaims: { groups: [group] },
  });

  test(`${name}: explicit sign-in requests the account picker`, async () => {
    const instance = createPortal(portal, []);
    await assert.rejects(vm.runInContext(portal.init, instance.context));
    vm.runInContext(portal.signIn, instance.context);
    assert.equal(instance.msal.loginRequest.prompt, 'select_account');
  });

  test(`${name}: multiple cached accounts require a choice`, async () => {
    const instance = createPortal(portal, [
      account('wrong@example.test', 'viewer-group'),
      account('right@example.test', 'admin-group'),
    ]);
    await assert.rejects(vm.runInContext(portal.init, instance.context));
    assert.equal(instance.requests.length, 0);
    assert.equal(instance.elements.get(portal.splash).style.display, 'flex');
  });

  test(`${name}: a single cached account keeps its existing session`, async () => {
    const user = account('right@example.test', 'admin-group');
    const instance = createPortal(portal, [user]);
    await vm.runInContext(portal.init, instance.context);
    assert.deepEqual(instance.requests, [user]);
  });

  test(`${name}: an active cached account is never replaced by the first account`, async () => {
    const wrong = account('wrong@example.test', 'viewer-group');
    const right = account('right@example.test', 'admin-group');
    const instance = createPortal(portal, [wrong, right]);
    instance.msal.setActiveAccount(right);
    await vm.runInContext(portal.init, instance.context);
    assert.deepEqual(instance.requests, [right]);
    vm.runInContext(portal.signIn, instance.context);
    assert.equal(instance.msal.loginRequest.prompt, 'select_account');
  });

  test(`${name}: redirect selects the account returned by MSAL`, async () => {
    const wrong = account('wrong@example.test', 'viewer-group');
    const right = account('right@example.test', 'admin-group');
    const instance = createPortal(portal, [wrong, right], { account: right, accessToken: 'fixture-token' });
    await vm.runInContext(portal.init, instance.context);
    assert.equal(instance.msal.activeAccount, right);
    assert.deepEqual(instance.requests, [right]);
  });
}
