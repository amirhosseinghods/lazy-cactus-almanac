import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Badge, Checkbox, useToast } from '@nasnet/ui';
import {
  ApiError,
  fetchIranSiteVpns,
  isAbortError,
  setIranSiteVpns,
  type IranSiteVpn,
  type VPNCredentials,
} from '../../../api';

/**
 * Tick boxes for the VPN clients Iranian sites may use. They are tried in the
 * order ticked; when none is up the router keeps the sites blocked.
 */
export function IranSiteVpnPicker({ creds }: { creds: VPNCredentials | null }) {
  const { t } = useTranslation('vpn');
  const toast = useToast();
  const [vpns, setVpns] = useState<IranSiteVpn[] | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!creds) return;
    const controller = new AbortController();
    fetchIranSiteVpns(creds, controller.signal)
      .then(setVpns)
      .catch((err) => {
        if (!isAbortError(err)) setVpns(null);
      });
    return () => controller.abort();
  }, [creds]);

  if (!vpns || !creds) return null;

  const ticked = vpns.filter((v) => v.order > 0).sort((a, b) => a.order - b.order);

  const toggle = async (v: IranSiteVpn) => {
    // Unticking drops it from the order; ticking adds it last.
    const next =
      v.order > 0
        ? ticked.filter((x) => x.name !== v.name).map((x) => x.name)
        : [...ticked.map((x) => x.name), v.name];
    setBusy(true);
    try {
      setVpns(await setIranSiteVpns(creds, next));
    } catch (err) {
      toast.notify({
        title: t('foreignSites.vpns.failed'),
        description: err instanceof ApiError || err instanceof Error ? err.message : undefined,
        tone: 'danger',
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ display: 'grid', gap: 8, marginTop: 20 }}>
      <strong>{t('foreignSites.vpns.title')}</strong>
      <span style={{ opacity: 0.8 }}>
        {ticked.length ? t('foreignSites.vpns.description') : t('foreignSites.vpns.noneTicked')}
      </span>
      {vpns.map((v) => (
        <div
          key={v.name}
          style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}
        >
          <Checkbox
            label={v.label}
            checked={v.order > 0}
            disabled={busy}
            onChange={() => toggle(v)}
          />
          {v.order > 0 ? (
            <Badge tone="neutral">{t('foreignSites.vpns.order', { n: v.order })}</Badge>
          ) : null}
          {v.inUse ? <Badge tone="success">{t('foreignSites.vpns.inUse')}</Badge> : null}
          {!v.running ? <Badge tone="warning">{t('foreignSites.vpns.down')}</Badge> : null}
        </div>
      ))}
      {ticked.length > 0 && !ticked.some((v) => v.inUse) ? (
        <Badge tone="danger">{t('foreignSites.vpns.allDown')}</Badge>
      ) : null}
    </div>
  );
}
