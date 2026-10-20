import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw } from 'lucide-react';
import { Button, Card, Switch, useToast } from '@nasnet/ui';
import {
  ApiError,
  fetchDNSLeakGuard,
  fetchIranIPList,
  isAbortError,
  setDNSLeakGuard,
  updateIranIPList,
  type IranIPListState,
  type VPNCredentials,
} from '../../../api';
import { useFormat } from '../../../utils/useFormat';
import { SectionHeader } from './SectionHeader';

interface Props {
  creds: VPNCredentials | null;
}

const errorMessage = (err: unknown, fallback: string) =>
  err instanceof ApiError ? err.message : err instanceof Error ? err.message : fallback;

/**
 * DNS leak protection and the Iranian IP list that decides which traffic the
 * Split networks send out the domestic link.
 */
export function SplitPrivacyCard({ creds }: Props) {
  const { t } = useTranslation('vpn');
  const toast = useToast();
  const format = useFormat();
  const [leakGuard, setLeakGuard] = useState<boolean | null>(null);
  const [iranList, setIranList] = useState<IranIPListState | null>(null);
  const [busy, setBusy] = useState<'guard' | 'list' | null>(null);

  useEffect(() => {
    if (!creds) return;
    const controller = new AbortController();
    fetchDNSLeakGuard(creds, controller.signal)
      .then((s) => setLeakGuard(s.enabled))
      .catch((err) => !isAbortError(err) && setLeakGuard(null));
    fetchIranIPList(creds, controller.signal)
      .then(setIranList)
      .catch((err) => !isAbortError(err) && setIranList(null));
    return () => controller.abort();
  }, [creds]);

  const toggleGuard = useCallback(
    async (enabled: boolean) => {
      if (!creds) return;
      setBusy('guard');
      try {
        const res = await setDNSLeakGuard(creds, enabled);
        setLeakGuard(res.enabled);
        toast.notify({
          title: enabled ? t('privacy.guardOn') : t('privacy.guardOff'),
          tone: 'success',
        });
      } catch (err) {
        toast.notify({
          title: t('privacy.guardFailed'),
          description: errorMessage(err, t('privacy.guardFailed')),
          tone: 'danger',
        });
      } finally {
        setBusy(null);
      }
    },
    [creds, t, toast],
  );

  const refreshList = useCallback(async () => {
    if (!creds) return;
    setBusy('list');
    try {
      const res = await updateIranIPList(creds);
      toast.notify({
        title: t('privacy.listUpdated', {
          total: format.number(res.total),
          added: format.number(res.added),
          removed: format.number(res.removed),
        }),
        tone: 'success',
      });
      setIranList(await fetchIranIPList(creds));
    } catch (err) {
      toast.notify({
        title: t('privacy.listFailed'),
        description: errorMessage(err, t('privacy.listFailed')),
        tone: 'danger',
      });
    } finally {
      setBusy(null);
    }
  }, [creds, format, t, toast]);

  if (leakGuard === null && iranList === null) return null;

  return (
    <Card>
      <SectionHeader title={t('privacy.title')} description={t('privacy.description')} />
      <div style={{ display: 'grid', gap: 'var(--space-md)', marginTop: 16 }}>
        {leakGuard !== null ? (
          <div style={{ display: 'grid', gap: 'var(--space-xs)' }}>
            <Switch
              label={t('privacy.guardToggle')}
              checked={leakGuard}
              disabled={!creds || busy !== null}
              onChange={(e) => {
                toggleGuard(e.target.checked);
              }}
            />
            <span style={{ color: 'var(--color-text-muted)', fontSize: 'var(--font-sm)' }}>
              {t('privacy.guardHint')}
            </span>
          </div>
        ) : null}
        {iranList ? (
          <div style={{ display: 'grid', gap: 'var(--space-xs)' }}>
            <div
              style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center' }}
              role="status"
            >
              <span>
                {t('privacy.listSummary', {
                  count: iranList.entries,
                  value: format.number(iranList.entries),
                })}
              </span>
              <span style={{ color: 'var(--color-text-muted)' }}>
                {iranList.managedByPanel && iranList.updatedAt
                  ? t('privacy.listUpdatedAt', {
                      date: format.dateTime(iranList.updatedAt, {
                        dateStyle: 'medium',
                        timeStyle: 'short',
                      }),
                    })
                  : t('privacy.listLegacy')}
              </span>
              <Button
                size="sm"
                variant="secondary"
                disabled={!creds || busy !== null}
                onClick={refreshList}
              >
                <RefreshCw size={14} aria-hidden />
                {busy === 'list' ? t('privacy.listUpdating') : t('privacy.listUpdate')}
              </Button>
            </div>
            <span style={{ color: 'var(--color-text-muted)', fontSize: 'var(--font-sm)' }}>
              {t('privacy.listHint')}
            </span>
          </div>
        ) : null}
      </div>
    </Card>
  );
}
