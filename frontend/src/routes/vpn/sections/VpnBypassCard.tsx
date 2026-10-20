import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Badge, Card, ConfirmDialog, Switch, useToast } from '@nasnet/ui';
import {
  ApiError,
  fetchVPNBypass,
  isAbortError,
  setVPNBypass,
  type VPNBypassState,
  type VPNCredentials,
} from '../../../api';
import { SectionHeader } from './SectionHeader';

interface Props {
  creds: VPNCredentials | null;
  /** Called after the bypass is turned on or off, since it changes the active VPN. */
  onChanged: () => void;
  /** Display name for a VPN client name. */
  labelFor: (name: string) => string;
}

/**
 * Emergency switch that sends VPN traffic straight out the foreign link
 * (Starlink) when the VPN is slow or down, and puts the previous VPN back
 * when turned off.
 */
export function VpnBypassCard({ creds, onChanged, labelFor }: Props) {
  const { t } = useTranslation('vpn');
  const toast = useToast();
  const [state, setState] = useState<VPNBypassState | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(false);

  useEffect(() => {
    if (!creds) return;
    const controller = new AbortController();
    fetchVPNBypass(creds, controller.signal)
      .then(setState)
      .catch((err) => {
        // Routers without the NasNet routing layout have nothing to bypass.
        if (!isAbortError(err)) setState(null);
      });
    return () => controller.abort();
  }, [creds]);

  const apply = useCallback(
    async (enabled: boolean) => {
      if (!creds) return;
      setBusy(true);
      try {
        const next = await setVPNBypass(creds, enabled);
        setState(next);
        toast.notify({
          title: enabled ? t('bypass.enabledToast') : t('bypass.disabledToast'),
          tone: enabled ? 'warning' : 'success',
        });
        onChanged();
      } catch (err) {
        toast.notify({
          title: t('bypass.failed'),
          description:
            err instanceof ApiError
              ? err.message
              : err instanceof Error
                ? err.message
                : t('bypass.failed'),
          tone: 'danger',
        });
      } finally {
        setBusy(false);
      }
    },
    [creds, onChanged, t, toast],
  );

  if (!state) return null;

  return (
    <Card>
      <SectionHeader title={t('bypass.title')} description={t('bypass.description')} />
      <div style={{ display: 'grid', gap: 'var(--space-sm)', marginTop: 16 }}>
        <Switch
          label={t('bypass.toggle')}
          checked={state.enabled}
          disabled={!creds || busy}
          onChange={(e) => {
            if (e.target.checked) {
              setConfirming(true);
            } else {
              apply(false);
            }
          }}
        />
        {state.enabled ? (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
            <Badge tone="warning">{t('bypass.activeBadge')}</Badge>
            <span>
              {state.restoreTo
                ? t('bypass.restoreTo', { name: labelFor(state.restoreTo) })
                : t('bypass.restoreUnknown')}
            </span>
          </div>
        ) : null}
      </div>
      <ConfirmDialog
        open={confirming}
        title={t('bypass.confirmTitle')}
        description={t('bypass.confirmDescription')}
        confirmLabel={t('bypass.confirm')}
        destructive
        onConfirm={() => {
          setConfirming(false);
          apply(true);
        }}
        onCancel={() => setConfirming(false)}
      />
    </Card>
  );
}
