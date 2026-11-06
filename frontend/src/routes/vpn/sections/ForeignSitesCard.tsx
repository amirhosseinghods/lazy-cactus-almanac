import { useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Card, Input, useToast } from '@nasnet/ui';
import {
  addForeignSite,
  ApiError,
  fetchForeignSites,
  isAbortError,
  removeForeignSite,
  type ForeignSite,
  type VPNCredentials,
} from '../../../api';
import { SectionHeader } from './SectionHeader';

interface Props {
  creds: VPNCredentials | null;
}

/** Sites the user adds by hand that skip the VPN and go out the foreign link (Starlink). */
export function ForeignSitesCard({ creds }: Props) {
  const { t } = useTranslation('vpn');
  const toast = useToast();
  const [sites, setSites] = useState<ForeignSite[] | null>(null);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!creds) return;
    const controller = new AbortController();
    fetchForeignSites(creds, controller.signal)
      .then(setSites)
      .catch((err) => {
        if (!isAbortError(err)) setSites(null);
      });
    return () => controller.abort();
  }, [creds]);

  const run = async (action: () => Promise<ForeignSite[]>, success: string) => {
    setBusy(true);
    try {
      setSites(await action());
      toast.notify({ title: success, tone: 'success' });
      return true;
    } catch (err) {
      toast.notify({
        title: t('foreignSites.failed'),
        description: err instanceof ApiError || err instanceof Error ? err.message : undefined,
        tone: 'danger',
      });
      return false;
    } finally {
      setBusy(false);
    }
  };

  const onAdd = async (e: FormEvent) => {
    e.preventDefault();
    const site = draft.trim();
    if (!creds || !site) return;
    if (await run(() => addForeignSite(creds, site), t('foreignSites.added', { site })))
      setDraft('');
  };

  if (!sites) return null;

  return (
    <Card>
      <SectionHeader title={t('foreignSites.title')} description={t('foreignSites.description')} />
      <form onSubmit={onAdd} style={{ display: 'flex', gap: 8, marginTop: 16 }}>
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={t('foreignSites.placeholder')}
          aria-label={t('foreignSites.inputLabel')}
          autoComplete="off"
          dir="ltr"
          style={{ flex: 1 }}
        />
        <Button type="submit" disabled={!creds || busy || !draft.trim()}>
          {t('foreignSites.add')}
        </Button>
      </form>
      <div style={{ display: 'grid', gap: 8, marginTop: 12 }}>
        {sites.length === 0 ? (
          <span style={{ opacity: 0.7 }}>{t('foreignSites.empty')}</span>
        ) : (
          sites.map((s) => (
            <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span dir="ltr" style={{ flex: 1, fontFamily: 'monospace' }}>
                {s.address}
              </span>
              <Button
                variant="ghost"
                size="sm"
                disabled={!creds || busy}
                onClick={() =>
                  creds &&
                  run(
                    () => removeForeignSite(creds, s.id),
                    t('foreignSites.removed', { site: s.address }),
                  )
                }
              >
                {t('foreignSites.remove')}
              </Button>
            </div>
          ))
        )}
      </div>
    </Card>
  );
}
