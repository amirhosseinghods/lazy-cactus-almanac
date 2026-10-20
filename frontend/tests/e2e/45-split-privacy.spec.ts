import { test, expect } from './fixtures';

const ROUTER_ID = 'rtr_privacy';

const envelope = <T>(data: T) => JSON.stringify({ status: 200, message: 'OK', data });

test.describe('Split routing and DNS privacy', () => {
  test('turns on DNS leak protection and updates the Iranian IP list', async ({
    page,
    context,
    resetMocks,
    seedRouter,
    seedCredentials,
  }) => {
    await resetMocks();
    await seedRouter({ id: ROUTER_ID, name: 'Privacy Router', host: '10.0.0.40' });
    await seedCredentials(ROUTER_ID);
    for (const path of ['**/api/interface/interfaces', '**/api/vpn/clients']) {
      await context.route(path, async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: envelope([]) });
      });
    }

    let guard = false;
    const guardPuts: boolean[] = [];
    await context.route('**/api/dns/leak-guard', async (route) => {
      if (route.request().method() === 'PUT') {
        guard = (route.request().postDataJSON() as { enabled: boolean }).enabled;
        guardPuts.push(guard);
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: envelope({ enabled: guard }),
      });
    });

    let list = { entries: 2180, managedByPanel: false, sources: ['a', 'b'] } as Record<
      string,
      unknown
    >;
    let updates = 0;
    await context.route('**/api/route/iran-ip', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope(list) });
    });
    await context.route('**/api/route/iran-ip/update', async (route) => {
      updates += 1;
      list = {
        entries: 1961,
        managedByPanel: true,
        updatedAt: '2026-10-21T00:00:00Z',
        sources: [],
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: envelope({
          total: 1961,
          added: 812,
          removed: 1031,
          updatedAt: '2026-10-21T00:00:00Z',
        }),
      });
    });

    await page.goto(`/router/${ROUTER_ID}/wan`);

    const toggle = page.getByRole('switch', { name: 'DNS leak protection' });
    await expect(toggle).not.toBeChecked();
    await toggle.click();
    await expect.poll(() => guardPuts).toEqual([true]);
    await expect(toggle).toBeChecked();

    await expect(page.getByText('Iranian IP list: 2,180 ranges')).toBeVisible();
    await expect(page.getByText("from the setup wizard's source")).toBeVisible();
    await page.getByRole('button', { name: 'Update from GitHub' }).click();
    await expect.poll(() => updates).toBe(1);
    await expect(
      page.getByRole('status').filter({
        hasText: 'Iranian IP list updated: 1,961 ranges (812 added, 1,031 removed)',
      }),
    ).toBeVisible();
    await expect(page.getByText('Iranian IP list: 1,961 ranges')).toBeVisible();
  });
});
