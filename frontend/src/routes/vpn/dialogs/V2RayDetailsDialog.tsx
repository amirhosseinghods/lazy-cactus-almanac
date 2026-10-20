import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw } from 'lucide-react';
import { Badge, Button, DataTable, Dialog, FormError, useToast } from '@nasnet/ui';
import {
  ApiError,
  fetchV2RayClientDetails,
  isAbortError,
  refreshV2RaySubscription,
  type V2RayClientDetails,
  type V2RayServer,
  type VPNClient,
  type VPNCredentials,
} from '../../../api';
import { useFormat } from '../../../utils/useFormat';

interface Props {
  client: VPNClient;
  creds: VPNCredentials | null;
  onClose: () => void;
}

const errorMessage = (err: unknown, fallback: string) =>
  err instanceof ApiError ? err.message : err instanceof Error ? err.message : fallback;

export function V2RayDetailsDialog({ client, creds, onClose }: Props) {
  const { t } = useTranslation('vpn');
  const toast = useToast();
  const format = useFormat();
  const [details, setDetails] = useState<V2RayClientDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    if (!creds) return;
    const controller = new AbortController();
    setError(null);
    fetchV2RayClientDetails(creds, client.name, controller.signal)
      .then(setDetails)
      .catch((err) => {
        if (!isAbortError(err)) setError(errorMessage(err, t('v2ray.loadFailed')));
      });
    return () => controller.abort();
  }, [creds, client.name, reloadKey, t]);

  const onRefresh = useCallback(async () => {
    if (!creds) return;
    setRefreshing(true);
    try {
      const res = await refreshV2RaySubscription(creds, client.name);
      toast.notify({
        title: res.changed
          ? t('v2ray.refreshChanged', { count: res.serverCount })
          : t('v2ray.refreshUnchanged'),
        tone: 'success',
      });
      setReloadKey((k) => k + 1);
    } catch (err) {
      toast.notify({
        title: t('v2ray.refreshFailed'),
        description: errorMessage(err, t('v2ray.refreshFailed')),
        tone: 'danger',
      });
    } finally {
      setRefreshing(false);
    }
  }, [creds, client.name, t, toast]);

  const isSubscription = details?.mode === 'subscription';
  const servers = details?.servers ?? [];
  const selected = servers.find((s) => s.selected);

  return (
    <Dialog
      open
      onClose={onClose}
      title={client.comment || client.name}
      size="md"
      footer={
        <>
          {isSubscription ? (
            <Button variant="secondary" onClick={onRefresh} disabled={!creds || refreshing}>
              <RefreshCw size={16} aria-hidden />
              {refreshing ? t('v2ray.refreshing') : t('v2ray.refresh')}
            </Button>
          ) : null}
          <Button onClick={onClose}>{t('shared.close')}</Button>
        </>
      }
    >
      {error ? <FormError role="alert">{error}</FormError> : null}
      {details ? (
        <div style={{ display: 'grid', gap: 'var(--space-md)' }}>
          <dl
            style={{
              display: 'grid',
              gridTemplateColumns: 'max-content 1fr',
              gap: 'var(--space-xs) var(--space-md)',
              margin: 0,
            }}
          >
            <dt>{t('v2ray.mode')}</dt>
            <dd style={{ margin: 0 }}>
              {isSubscription ? t('v2ray.modeSubscription') : t('v2ray.modeLink')}
            </dd>
            {isSubscription ? (
              <>
                <dt>{t('v2ray.serverCount')}</dt>
                <dd style={{ margin: 0 }}>
                  {format.number(servers.length)}
                  {details.skipped
                    ? ` ${t('v2ray.skipped', { count: details.skipped, value: format.number(details.skipped) })}`
                    : ''}
                </dd>
                <dt>{t('v2ray.activeServer')}</dt>
                <dd style={{ margin: 0 }} dir="auto">
                  {selected ? selected.name || selected.server : t('v2ray.activeUnknown')}
                </dd>
                <dt>{t('v2ray.lastRefresh')}</dt>
                <dd style={{ margin: 0 }}>
                  {details.refreshedAt
                    ? format.dateTime(details.refreshedAt, {
                        dateStyle: 'medium',
                        timeStyle: 'short',
                      })
                    : '—'}
                </dd>
              </>
            ) : (
              <>
                <dt>{t('shared.protocol')}</dt>
                <dd style={{ margin: 0 }}>{details.protocol.toUpperCase()}</dd>
                <dt>{t('v2ray.server')}</dt>
                <dd style={{ margin: 0 }} dir="ltr">
                  {details.server}
                </dd>
              </>
            )}
          </dl>
          {isSubscription && servers.length > 0 ? (
            <DataTable<V2RayServer>
              columns={[
                {
                  key: 'name',
                  header: t('shared.name'),
                  render: (s) => <span dir="auto">{s.name || '—'}</span>,
                },
                {
                  key: 'protocol',
                  header: t('shared.protocol'),
                  render: (s) => <Badge tone="info">{s.protocol.toUpperCase()}</Badge>,
                  width: '120px',
                },
                {
                  key: 'state',
                  header: t('v2ray.state'),
                  render: (s) =>
                    s.selected ? <Badge tone="success">{t('v2ray.inUse')}</Badge> : null,
                  width: '100px',
                },
              ]}
              rows={servers}
              rowKey={(s) => `${s.server}|${s.name ?? ''}`}
            />
          ) : null}
          <p style={{ margin: 0, color: 'var(--color-text-muted)', fontSize: 'var(--font-sm)' }}>
            {isSubscription ? t('v2ray.autoSwitchNote') : t('v2ray.leakNote')}
          </p>
        </div>
      ) : null}
    </Dialog>
  );
}
