import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Card, ConfirmDialog, Progress, Stack, useToast } from '@nasnet/ui';
import {
  ApiError,
  addL2TPClient,
  addV2RayClient,
  createWireguardClient,
  deleteL2TPClient,
  deleteV2RayClient,
  deleteWireguardInterface,
  fetchV2RayClientStatus,
  importWireguardConfig,
  updateL2TPClient,
  type AddL2TPClientRequest,
  type AddV2RayClientRequest,
  type CreateWireguardClientRequest,
  type CreateWireguardClientResponse,
  type ImportWireguardConfigRequest,
  type ImportWireguardConfigResponse,
  type UpdateL2TPClientRequest,
  type V2RayClientTaskStatus,
  type VPNClient,
  type VPNClientResponse,
  type VPNCredentials,
} from '../../../api';
import { AddVpnClientDialog } from '../dialogs/AddVpnClientDialog';
import { EditL2tpClientDialog } from '../dialogs/EditL2tpClientDialog';
import { EditWgClientDialog } from '../dialogs/EditWgClientDialog';
import { V2RayDetailsDialog } from '../dialogs/V2RayDetailsDialog';
import { useFormat } from '../../../utils/useFormat';
import { PaginationControls } from '../PaginationControls';
import { usePagedFilter } from '../hooks/usePagedFilter';
import { PAGE_SIZE } from '../utils';
import { summarizeWireguardImport } from '../wgClientSummary';
import { ClientsTable } from './ClientsTable';
import { SectionHeader } from './SectionHeader';
import { VpnBypassCard } from './VpnBypassCard';

const V2RAY_POLL_INTERVAL_MS = 2000;

/** Setup phases reported by the backend, in order, mapped to their labels. */
const V2RAY_PHASES = [
  'preparing',
  'fetching_subscription',
  'downloading',
  'creating_interface',
  'writing_config',
  'creating_container',
  'pulling',
  'starting',
] as const;

interface V2RaySetup {
  label: string;
  status: V2RayClientTaskStatus | null;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const matches = (c: VPNClient, q: string) =>
  c.name.toLowerCase().includes(q) ||
  (c.endpoint ?? '').toLowerCase().includes(q) ||
  (c.username ?? '').toLowerCase().includes(q) ||
  (c.comment ?? '').toLowerCase().includes(q);

interface Props {
  creds: VPNCredentials | null;
  clients: VPNClient[];
  onChanged: () => void;
  onClientUpdated: (client: VPNClient) => void;
  onDialogOpenChange?: (open: boolean) => void;
}

export function ClientsSection({
  creds,
  clients,
  onChanged,
  onClientUpdated,
  onDialogOpenChange,
}: Props) {
  const paged = usePagedFilter(clients, matches);
  const toast = useToast();
  const { t } = useTranslation('vpn');
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<VPNClient | null>(null);
  const [pendingDelete, setPendingDelete] = useState<VPNClient | null>(null);
  const [deleteSubmitting, setDeleteSubmitting] = useState(false);
  const [v2raySetup, setV2RaySetup] = useState<V2RaySetup | null>(null);
  const format = useFormat();

  const dialogOpen = adding || editing !== null || pendingDelete !== null;
  useEffect(() => {
    onDialogOpenChange?.(dialogOpen);
  }, [dialogOpen, onDialogOpenChange]);

  const onSubmitL2TP = async (req: AddL2TPClientRequest) => {
    if (!creds) {
      toast.notify({ title: t('shared.notConnected'), tone: 'danger' });
      return;
    }
    let created: VPNClientResponse;
    try {
      created = await addL2TPClient(creds, req);
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : t('clients.toast.addL2tpFailedDescription');
      toast.notify({ title: t('clients.toast.addFailed'), description: message, tone: 'danger' });
      throw err;
    }
    setAdding(false);
    toast.notify({ title: t('clients.toast.l2tpAdded', { name: created.name }), tone: 'success' });
    onChanged();
  };

  const onSubmitWireguard = async (req: CreateWireguardClientRequest) => {
    if (!creds) {
      toast.notify({ title: t('shared.notConnected'), tone: 'danger' });
      return;
    }
    let created: CreateWireguardClientResponse;
    try {
      created = await createWireguardClient(creds, req);
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : t('clients.toast.addWgFailedDescription');
      toast.notify({ title: t('clients.toast.addFailed'), description: message, tone: 'danger' });
      throw err;
    }
    setAdding(false);
    toast.notify({ title: t('clients.toast.wgAdded', { name: created.name }), tone: 'success' });
    onChanged();
  };

  const onSubmitWireguardImport = async (req: ImportWireguardConfigRequest) => {
    if (!creds) {
      toast.notify({ title: t('shared.notConnected'), tone: 'danger' });
      return;
    }
    let imported: ImportWireguardConfigResponse;
    try {
      imported = await importWireguardConfig(creds, req);
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : t('clients.toast.wgImportFailed');
      toast.notify({
        title: t('clients.toast.wgImportFailedTitle'),
        description: message,
        tone: 'danger',
      });
      throw err;
    }
    setAdding(false);
    toast.notify({
      ...summarizeWireguardImport(imported.interfaceName, imported),
      durationMs: 8000,
    });
    onChanged();
  };

  const onSubmitV2Ray = async (req: AddV2RayClientRequest) => {
    if (!creds) {
      toast.notify({ title: t('shared.notConnected'), tone: 'danger' });
      return;
    }
    const fail = (err: unknown) => {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : t('clients.toast.addV2rayFailedDescription');
      toast.notify({ title: t('clients.toast.v2rayFailed'), description: message, tone: 'danger' });
    };
    let name: string;
    try {
      ({ name } = await addV2RayClient(creds, req));
    } catch (err) {
      fail(err);
      throw err;
    }
    // The panel now downloads the subscription and the sing-box image in the
    // background; close the dialog and show live progress above the table.
    const label = req.comment || name;
    setAdding(false);
    setV2RaySetup({ label, status: null });
    onChanged();
    for (;;) {
      await sleep(V2RAY_POLL_INTERVAL_MS);
      let status: V2RayClientTaskStatus;
      try {
        status = await fetchV2RayClientStatus(creds, name);
      } catch (err) {
        setV2RaySetup(null);
        fail(err);
        return;
      }
      if (!status.done) {
        setV2RaySetup({ label, status });
        continue;
      }
      setV2RaySetup(null);
      if (status.failed) {
        fail(new Error(status.message));
      } else {
        toast.notify({
          title: t('clients.toast.v2rayAdded', { name: label }),
          tone: 'success',
        });
      }
      onChanged();
      return;
    }
  };

  const onSubmitEdit = async (req: UpdateL2TPClientRequest) => {
    if (!creds || !editing) {
      toast.notify({ title: t('shared.notConnected'), tone: 'danger' });
      return;
    }
    const target = editing;
    try {
      await updateL2TPClient(creds, target.id, req);
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : t('clients.toast.l2tpUpdateFailedDescription');
      toast.notify({
        title: t('clients.toast.l2tpUpdateFailed'),
        description: message,
        tone: 'danger',
      });
      throw err;
    }
    setEditing(null);
    toast.notify({ title: t('clients.toast.l2tpUpdated', { name: target.name }), tone: 'success' });
    onClientUpdated({
      ...target,
      comment: req.comment ?? target.comment,
      enabled: req.disabled === undefined ? target.enabled : !req.disabled,
    });
  };

  const onConfirmDelete = async () => {
    if (!creds || !pendingDelete) return;
    const target = pendingDelete;
    setDeleteSubmitting(true);
    try {
      if (target.protocol === 'wireguard') {
        await deleteWireguardInterface(creds, target.name);
      } else if (target.protocol === 'v2ray') {
        await deleteV2RayClient(creds, target.name);
      } else {
        await deleteL2TPClient(creds, target.id);
      }
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : t('clients.toast.deleteFailedDescription');
      toast.notify({
        title: t('clients.toast.deleteFailed'),
        description: message,
        tone: 'danger',
      });
      setDeleteSubmitting(false);
      return;
    }
    setDeleteSubmitting(false);
    setPendingDelete(null);
    toast.notify({ title: t('clients.toast.deletedNamed', { name: target.name }), tone: 'info' });
    onChanged();
  };

  return (
    <Stack>
      <VpnBypassCard
        creds={creds}
        onChanged={onChanged}
        labelFor={(name) => clients.find((c) => c.name === name)?.comment || name}
      />
      <Card>
        <SectionHeader
          title={t('clients.title')}
          description={t('clients.description')}
          action={{
            label: t('clients.new'),
            disabled: !creds,
            onClick: () => setAdding(true),
          }}
        />
        {v2raySetup ? (
          <V2RaySetupProgress
            setup={v2raySetup}
            describe={(status) => {
              const phase = V2RAY_PHASES.find((p) => p === status?.phase) ?? 'preparing';
              if (phase === 'downloading' && status?.bytesTotal) {
                return t('v2ray.setup.downloadingBytes', {
                  done: format.number((status.bytesDone ?? 0) / 1048576, {
                    maximumFractionDigits: 1,
                  }),
                  total: format.number(status.bytesTotal / 1048576, { maximumFractionDigits: 1 }),
                });
              }
              return t(`v2ray.setup.${phase}`);
            }}
          />
        ) : null}
        <div style={{ marginTop: 16 }}>
          <ClientsTable
            rows={paged.pagedRows}
            totalRows={clients.length}
            creds={creds}
            onToggled={onChanged}
            onEdit={(c) => setEditing(c)}
            onDelete={(c) => setPendingDelete(c)}
          />
          <PaginationControls
            page={paged.page}
            totalPages={paged.totalPages}
            total={paged.filteredCount}
            pageSize={PAGE_SIZE}
            onPrev={paged.onPrev}
            onNext={paged.onNext}
          />
        </div>
      </Card>
      {adding ? (
        <AddVpnClientDialog
          onCancel={() => setAdding(false)}
          onSubmitL2TP={onSubmitL2TP}
          onSubmitWireguard={onSubmitWireguard}
          onSubmitWireguardImport={onSubmitWireguardImport}
          onSubmitV2Ray={onSubmitV2Ray}
        />
      ) : null}
      {editing && editing.protocol === 'l2tp' ? (
        <EditL2tpClientDialog
          clientName={editing.name}
          creds={creds}
          onCancel={() => setEditing(null)}
          onSubmit={onSubmitEdit}
        />
      ) : null}
      {editing && editing.protocol === 'wireguard' ? (
        <EditWgClientDialog
          creds={creds}
          client={editing}
          onCancel={() => setEditing(null)}
          onSaved={(changes) => {
            const target = editing;
            setEditing(null);
            toast.notify({
              title: t('clients.toast.wgUpdated', { name: target.name }),
              tone: 'success',
            });
            onClientUpdated({ ...target, comment: changes.comment, enabled: !changes.disabled });
          }}
        />
      ) : null}
      {editing && editing.protocol === 'v2ray' ? (
        <V2RayDetailsDialog
          client={editing}
          creds={creds}
          onClose={() => {
            setEditing(null);
            onChanged();
          }}
        />
      ) : null}
      <ConfirmDialog
        open={!!pendingDelete}
        title={
          pendingDelete?.protocol === 'wireguard'
            ? t('clients.delete.wgTitle')
            : pendingDelete?.protocol === 'v2ray'
              ? t('clients.delete.v2rayTitle')
              : t('clients.delete.l2tpTitle')
        }
        description={
          pendingDelete
            ? pendingDelete.protocol === 'wireguard'
              ? t('clients.delete.wgDescription', { name: pendingDelete.name })
              : pendingDelete.protocol === 'v2ray'
                ? t('clients.delete.v2rayDescription', {
                    name: pendingDelete.comment || pendingDelete.name,
                  })
                : t('clients.delete.l2tpDescription', { name: pendingDelete.name })
            : undefined
        }
        confirmLabel={deleteSubmitting ? t('shared.deleting') : t('shared.delete')}
        destructive
        onConfirm={onConfirmDelete}
        onCancel={() => (deleteSubmitting ? undefined : setPendingDelete(null))}
      />
    </Stack>
  );
}

function V2RaySetupProgress({
  setup,
  describe,
}: {
  setup: V2RaySetup;
  describe: (status: V2RayClientTaskStatus | null) => string;
}) {
  const { t } = useTranslation('vpn');
  const { status } = setup;
  const step = Math.max(0, V2RAY_PHASES.indexOf((status?.phase ?? 'preparing') as never));
  // Within the download, advance by bytes; otherwise by finished steps.
  const downloadFraction =
    status?.phase === 'downloading' && status.bytesTotal
      ? (status.bytesDone ?? 0) / status.bytesTotal
      : 0;
  const value = Math.round(((step + downloadFraction) / V2RAY_PHASES.length) * 100);
  return (
    <div role="status" style={{ marginTop: 16 }}>
      <Progress
        value={value}
        label={`${t('clients.toast.v2rayCreating', { name: setup.label })}: ${describe(status)}`}
      />
    </div>
  );
}
