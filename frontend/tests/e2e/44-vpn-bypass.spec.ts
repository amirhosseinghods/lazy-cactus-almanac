import { test, expect } from './fixtures';

const ROUTER_ID = 'rtr_bypass';

const envelope = <T>(data: T) => JSON.stringify({ status: 200, message: 'OK', data });

test.describe('Emergency VPN bypass', () => {
  test('asks for confirmation, bypasses the VPN and restores it', async ({
    page,
    context,
    resetMocks,
    seedRouter,
    seedCredentials,
  }) => {
    await resetMocks();
    await seedRouter({ id: ROUTER_ID, name: 'Bypass Router', host: '10.0.0.30' });
    await seedCredentials(ROUTER_ID);
    await context.route('**/api/interface/interfaces', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope([]) });
    });
    await context.route('**/api/vpn/clients', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: envelope([
          {
            id: '*1',
            name: 'elder-josephine-l2tp-client',
            type: 'l2tp-out',
            running: true,
            disabled: false,
            rxByte: 0,
            txByte: 0,
            rxPacket: 0,
            txPacket: 0,
            comment: 'austria',
          },
        ]),
      });
    });

    let state: { enabled: boolean; restoreTo?: string } = { enabled: false };
    const puts: boolean[] = [];
    await context.route('**/api/route/vpn-bypass', async (route) => {
      if (route.request().method() === 'PUT') {
        const { enabled } = route.request().postDataJSON() as { enabled: boolean };
        puts.push(enabled);
        state = enabled ? { enabled, restoreTo: 'elder-josephine-l2tp-client' } : { enabled };
      }
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope(state) });
    });

    await page.goto(`/router/${ROUTER_ID}/wan`);
    const toggle = page.getByRole('switch', { name: 'Use Starlink directly, without VPN' });
    await expect(toggle).not.toBeChecked();

    // Cancelling the confirmation changes nothing.
    await toggle.click();
    const confirm = page.getByRole('dialog');
    await expect(confirm.getByText('Turn off the VPN?')).toBeVisible();
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    expect(puts).toEqual([]);
    await expect(toggle).not.toBeChecked();

    await toggle.click();
    await page.getByRole('dialog').getByRole('button', { name: 'Use Starlink directly' }).click();
    await expect.poll(() => puts).toEqual([true]);
    await expect(toggle).toBeChecked();
    await expect(page.getByText('VPN is off')).toBeVisible();
    await expect(page.getByText('Turning this off goes back to austria.')).toBeVisible();

    await toggle.click();
    await expect.poll(() => puts).toEqual([true, false]);
    await expect(toggle).not.toBeChecked();
    await expect(page.getByText('VPN is off')).toBeHidden();
  });

  test('stays hidden on routers without the routing layout', async ({
    page,
    context,
    resetMocks,
    seedRouter,
    seedCredentials,
  }) => {
    await resetMocks();
    await seedRouter({ id: ROUTER_ID, name: 'Bypass Router', host: '10.0.0.30' });
    await seedCredentials(ROUTER_ID);
    await context.route('**/api/interface/interfaces', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope([]) });
    });
    await context.route('**/api/vpn/clients', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope([]) });
    });
    await context.route('**/api/route/vpn-bypass', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ status: 500, message: 'no default route for the foreign link' }),
      });
    });

    await page.goto(`/router/${ROUTER_ID}/wan`);
    await expect(page.getByRole('heading', { name: 'Starlink Masking VPN Client' })).toBeVisible();
    await expect(
      page.getByRole('switch', { name: 'Use Starlink directly, without VPN' }),
    ).toHaveCount(0);
  });
});
