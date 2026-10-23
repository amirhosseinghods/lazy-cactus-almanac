import type { BrowserContext } from '@playwright/test';
import { test, expect } from './fixtures';

const ROUTER_ID = 'rtr_v2ray';

const envelope = <T>(data: T, status = 200) => JSON.stringify({ status, message: 'OK', data });

const VLESS_LINK =
  'vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443?security=reality' +
  '&sni=www.microsoft.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123abcd#Germany';

const v2rayClient = {
  id: '*A',
  name: 'v2ray-brave-otter',
  type: 'v2ray',
  running: true,
  disabled: false,
  rxByte: 0,
  txByte: 0,
  rxPacket: 0,
  txPacket: 0,
  comment: 'Germany',
};

async function signIn(context: BrowserContext) {
  await context.addInitScript((routerId) => {
    try {
      const key = 'nasnet-panel.session-credentials.v1';
      const raw = window.sessionStorage.getItem(key);
      const map = (raw ? JSON.parse(raw) : {}) as Record<
        string,
        { username: string; password: string }
      >;
      map[routerId] = { username: 'admin', password: 'test' };
      window.sessionStorage.setItem(key, JSON.stringify(map));
    } catch {
      /* ignore */
    }
  }, ROUTER_ID);
  await context.route('**/api/interface/interfaces', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: envelope([]) });
  });
}

test.describe('V2Ray VPN clients', () => {
  test('adds a client from a share link and reports when the container is ready', async ({
    page,
    context,
    resetMocks,
    seedRouter,
  }) => {
    await resetMocks();
    await seedRouter({ id: ROUTER_ID, name: 'V2Ray Router', host: '10.0.0.20' });
    await signIn(context);

    let created = false;
    await context.route('**/api/vpn/clients', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: envelope(created ? [v2rayClient] : []),
      });
    });

    const posts: Array<Record<string, unknown>> = [];
    await context.route('**/api/vpn/v2ray/client', async (route) => {
      if (route.request().method() !== 'POST') return route.fallback();
      posts.push(route.request().postDataJSON() as Record<string, unknown>);
      created = true;
      await route.fulfill({
        status: 202,
        contentType: 'application/json',
        body: envelope(
          { name: v2rayClient.name, phase: 'preparing', message: '', done: false, failed: false },
          202,
        ),
      });
    });

    let statusCalls = 0;
    await context.route(`**/api/vpn/v2ray/client/status/${v2rayClient.name}`, async (route) => {
      statusCalls += 1;
      const done = statusCalls > 1;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: envelope({
          name: v2rayClient.name,
          phase: done ? 'done' : 'pulling',
          message: done ? 'V2Ray client ready' : 'downloading',
          done,
          failed: false,
        }),
      });
    });

    await page.goto(`/router/${ROUTER_ID}/wan`);
    await page.getByRole('button', { name: 'New' }).click();
    const dialog = page.getByRole('dialog');
    await dialog
      .getByRole('radiogroup', { name: 'VPN client type' })
      .getByRole('radio', { name: 'V2Ray' })
      .click();

    await dialog.getByLabel('Name').fill('Germany');
    await dialog.getByRole('textbox', { name: 'Share link' }).fill(VLESS_LINK);
    await expect(dialog.getByText('Detected protocol: VLESS')).toBeVisible();
    await dialog.getByRole('button', { name: 'Add client' }).click();

    await expect.poll(() => posts.length).toBe(1);
    expect(posts[0]).toEqual({ link: VLESS_LINK, comment: 'Germany', disabled: false });
    await expect(dialog).toBeHidden();
    await expect(
      page.getByRole('progressbar', {
        name: 'Setting up V2Ray client "Germany": unpacking sing-box…',
      }),
    ).toBeVisible();

    await expect(
      page.getByRole('status').filter({ hasText: 'V2Ray client "Germany" is ready' }),
    ).toBeVisible({ timeout: 15_000 });
    const row = page.getByRole('row', { name: /v2ray-brave-otter/ });
    await expect(row.getByText('V2RAY', { exact: true })).toBeVisible();
    // V2Ray clients are recreated rather than edited; they get a details view instead.
    await expect(row.getByRole('button', { name: /edit/i })).toHaveCount(0);
    await expect(row.getByRole('button', { name: 'Details for Germany' })).toBeVisible();
  });

  test('rejects links with an unsupported scheme without calling the backend', async ({
    page,
    context,
    resetMocks,
    seedRouter,
  }) => {
    await resetMocks();
    await seedRouter({ id: ROUTER_ID, name: 'V2Ray Router', host: '10.0.0.20' });
    await signIn(context);
    await context.route('**/api/vpn/clients', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope([]) });
    });
    let posts = 0;
    await context.route('**/api/vpn/v2ray/client', async (route) => {
      posts += 1;
      await route.fulfill({ status: 500, body: '' });
    });

    await page.goto(`/router/${ROUTER_ID}/wan`);
    await page.getByRole('button', { name: 'New' }).click();
    const dialog = page.getByRole('dialog');
    await dialog
      .getByRole('radiogroup', { name: 'VPN client type' })
      .getByRole('radio', { name: 'V2Ray' })
      .click();
    const linkInput = dialog.getByRole('textbox', { name: 'Share link' });
    await linkInput.fill('socks5://user@host:1080');
    await linkInput.blur();

    await expect(dialog.getByText(/Unsupported link/)).toBeVisible();
    await expect(dialog.getByRole('button', { name: 'Add client' })).toBeDisabled();
    expect(posts).toBe(0);
  });

  test('deletes a client through the V2Ray endpoint after confirm', async ({
    page,
    context,
    resetMocks,
    seedRouter,
  }) => {
    await resetMocks();
    await seedRouter({ id: ROUTER_ID, name: 'V2Ray Router', host: '10.0.0.20' });
    await signIn(context);

    let deleted = false;
    await context.route('**/api/vpn/clients', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: envelope(deleted ? [] : [v2rayClient]),
      });
    });
    let deleteCalls = 0;
    await context.route(`**/api/vpn/v2ray/client/${v2rayClient.name}`, async (route) => {
      if (route.request().method() !== 'DELETE') return route.fallback();
      deleteCalls += 1;
      deleted = true;
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope(null) });
    });

    await page.goto(`/router/${ROUTER_ID}/wan`);
    const row = page.getByRole('row', { name: /v2ray-brave-otter/ });
    await row.getByRole('button', { name: /delete v2ray-brave-otter/i }).click();

    const confirm = page.getByRole('dialog');
    await expect(confirm.getByText('Delete V2Ray client')).toBeVisible();
    await confirm.getByRole('button', { name: 'Delete' }).click();

    await expect.poll(() => deleteCalls).toBe(1);
    await expect(page.getByRole('row', { name: /v2ray-brave-otter/ })).toBeHidden();
  });

  test('adds a client from a subscription URL', async ({
    page,
    context,
    resetMocks,
    seedRouter,
  }) => {
    await resetMocks();
    await seedRouter({ id: ROUTER_ID, name: 'V2Ray Router', host: '10.0.0.20' });
    await signIn(context);
    await context.route('**/api/vpn/clients', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope([]) });
    });
    const posts: Array<Record<string, unknown>> = [];
    await context.route('**/api/vpn/v2ray/client', async (route) => {
      if (route.request().method() !== 'POST') return route.fallback();
      posts.push(route.request().postDataJSON() as Record<string, unknown>);
      await route.fulfill({
        status: 202,
        contentType: 'application/json',
        body: envelope(
          { name: 'v2ray-sub-one', phase: 'preparing', message: '', done: false, failed: false },
          202,
        ),
      });
    });
    await context.route('**/api/vpn/v2ray/client/status/v2ray-sub-one', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: envelope({
          name: 'v2ray-sub-one',
          phase: 'done',
          message: '',
          done: true,
          failed: false,
        }),
      });
    });

    await page.goto(`/router/${ROUTER_ID}/wan`);
    await page.getByRole('button', { name: 'New' }).click();
    const dialog = page.getByRole('dialog');
    await dialog
      .getByRole('radiogroup', { name: 'VPN client type' })
      .getByRole('radio', { name: 'V2Ray' })
      .click();
    await dialog.getByRole('switch', { name: 'Use a subscription link' }).check();

    const url = dialog.getByRole('textbox', { name: 'Subscription URL' });
    await url.fill('not a url');
    await url.blur();
    await expect(dialog.getByText('Enter an http:// or https:// URL.')).toBeVisible();
    await expect(dialog.getByRole('button', { name: 'Add client' })).toBeDisabled();

    await url.fill('https://sub.example.com/s/abc');
    await dialog.getByLabel('Name').fill('My subscription');
    await dialog.getByRole('button', { name: 'Add client' }).click();

    await expect.poll(() => posts.length).toBe(1);
    expect(posts[0]).toEqual({
      subscription: 'https://sub.example.com/s/abc',
      comment: 'My subscription',
      disabled: false,
    });
  });

  test('shows subscription servers and refreshes on demand', async ({
    page,
    context,
    resetMocks,
    seedRouter,
  }) => {
    await resetMocks();
    await seedRouter({ id: ROUTER_ID, name: 'V2Ray Router', host: '10.0.0.20' });
    await signIn(context);
    await context.route('**/api/vpn/clients', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: envelope([v2rayClient]),
      });
    });
    await context.route(`**/api/vpn/v2ray/client/${v2rayClient.name}`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: envelope({
          name: v2rayClient.name,
          comment: 'Germany',
          mode: 'subscription',
          protocol: 'vless',
          server: 'de1.example.com:443',
          running: true,
          disabled: false,
          pulling: false,
          skipped: 1,
          refreshedAt: '2026-10-20T10:00:00Z',
          manual: false,
          canSelect: true,
          servers: [
            { name: 'DE 1', protocol: 'vless', server: 'de1.example.com:443', selected: false },
            {
              name: 'NL 1',
              protocol: 'trojan',
              server: 'nl1.example.com:443',
              selected: true,
              delayMs: 182,
            },
          ],
        }),
      });
    });
    const selections: unknown[] = [];
    await context.route(`**/api/vpn/v2ray/client/${v2rayClient.name}/server`, async (route) => {
      selections.push(route.request().postDataJSON());
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope(null) });
    });
    let refreshes = 0;
    await context.route(`**/api/vpn/v2ray/client/${v2rayClient.name}/refresh`, async (route) => {
      refreshes += 1;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: envelope({
          changed: false,
          serverCount: 2,
          refreshedAt: '2026-10-20T12:00:00Z',
        }),
      });
    });

    await page.goto(`/router/${ROUTER_ID}/wan`);
    await page
      .getByRole('row', { name: /v2ray-brave-otter/ })
      .getByRole('button', { name: 'Details for Germany' })
      .click();

    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Automatic (fastest server)')).toBeVisible();
    await expect(dialog.getByRole('row', { name: /NL 1/ }).getByText('In use')).toBeVisible();
    await expect(dialog.getByRole('row', { name: /NL 1/ }).getByText('182 ms')).toBeVisible();
    await expect(dialog.getByRole('row', { name: /DE 1/ }).getByText('No reply')).toBeVisible();

    await dialog.getByRole('button', { name: 'Use DE 1' }).click();
    await expect.poll(() => selections).toEqual([{ server: 0 }]);

    await dialog.getByRole('button', { name: 'Refresh now' }).click();
    await expect.poll(() => refreshes).toBe(1);
    await expect(
      page.getByRole('status').filter({ hasText: 'Server list is unchanged' }),
    ).toBeVisible();
  });
});
