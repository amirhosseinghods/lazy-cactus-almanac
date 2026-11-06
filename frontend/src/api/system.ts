import type { SystemOverview } from '../mocks/types';
import type { VPNClientResponse } from './vpn';
import { formatBytes } from '../utils/format';
import { apiRequest } from './http';

export interface SystemCredentials {
  host: string;
  username: string;
  password: string;
}

export interface SystemInfoResponse {
  identity: string;
  architecture: string;
  boardName: string;
  version: string;
  buildTime: string;
  license: string;
  updateChannel: string;
  systemId: string;
}

export interface ResourceInfoResponse {
  uptime: string;
  cpuCount: number;
  cpuLoad: number;
  cpuFrequency: string;
  memoryTotal: string;
  memoryUsed: string;
  memoryFree: string;
  memoryTotalBytes: number;
  memoryUsedBytes: number;
  memoryFreeBytes: number;
  hddTotal: string;
  hddFree: string;
  hddTotalBytes: number;
  hddFreeBytes: number;
  badBlocks: string;
  version: string;
  architecture: string;
  boardName: string;
}

export interface DHCPLeaseResponse {
  id: string;
  address: string;
  macAddress: string;
  hostName?: string;
  status: string;
  dynamic: boolean;
}

function authHeaders({ host, username, password }: SystemCredentials): Record<string, string> {
  return {
    Authorization: `Basic ${btoa(`${username}:${password}`)}`,
    'X-RouterOS-Host': host,
  };
}

export async function fetchSystemInfo(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<SystemInfoResponse> {
  return apiRequest<SystemInfoResponse>('/api/system/info', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
}

export async function fetchSystemResources(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<ResourceInfoResponse> {
  return apiRequest<ResourceInfoResponse>('/api/system/resources', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
}

export async function fetchDHCPLeases(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<DHCPLeaseResponse[]> {
  const leases = await apiRequest<DHCPLeaseResponse[] | null>('/api/dhcp/leases', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
  return leases ?? [];
}

export interface InterfaceGraphSample {
  rxBytes: number;
  txBytes: number;
  rx: string;
  tx: string;
  timestamp: string;
}

export interface InterfaceGraphResponse {
  interfaceName: string;
  trafficData: InterfaceGraphSample[] | null;
}

export interface InterfaceResponse {
  id: string;
  name: string;
  defaultName?: string;
  type: string;
  running: boolean;
  disabled: boolean;
  mac?: string;
  mtu?: number;
  comment?: string;
  rx?: string;
  tx?: string;
  actualMtu?: number;
}

export interface IpAddressResponse {
  id: string;
  address: string;
  interface: string;
  dynamic: boolean;
  disabled: boolean;
}

export async function fetchInterfaces(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<InterfaceResponse[]> {
  const list = await apiRequest<InterfaceResponse[] | null>('/api/interface/interfaces', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
  return list ?? [];
}

export interface EthernetInterfaceResponse {
  id?: string;
  name?: string;
  defaultName?: string;
  running?: boolean;
  disabled?: boolean;
  status?: string;
  rate?: string;
  fullDuplex?: boolean;
}

export async function fetchEthernetInterfaces(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<EthernetInterfaceResponse[]> {
  const list = await apiRequest<EthernetInterfaceResponse[] | null>('/api/interface/ethernets', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
  return list ?? [];
}

export interface CableTestResponse {
  name: string;
  status: string;
  cablePairs?: string;
}

export async function testEthernetCable(
  creds: SystemCredentials,
  nameOrId: string,
): Promise<CableTestResponse> {
  return apiRequest<CableTestResponse>(
    `/api/interface/ethernet/cable-test/${encodeURIComponent(nameOrId)}`,
    {
      method: 'POST',
      headers: authHeaders(creds),
      cache: 'no-store',
    },
  );
}

export async function resetInterfaceTrafficCounter(
  creds: SystemCredentials,
  nameOrId: string,
): Promise<void> {
  await apiRequest<void>(`/api/interface/traffic-counter/${encodeURIComponent(nameOrId)}`, {
    method: 'DELETE',
    headers: authHeaders(creds),
  });
}

export type WanInterfaceType = 'foreign' | 'domestic';

export interface UpdateWanInterfaceRequest {
  interface: string;
  type: WanInterfaceType;
  ssid?: string;
  password?: string;
}

export async function updateWanInterface(
  creds: SystemCredentials,
  request: UpdateWanInterfaceRequest,
): Promise<void> {
  await apiRequest<unknown>('/api/interface/wan', {
    method: 'PUT',
    headers: {
      ...authHeaders(creds),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });
}

export interface BridgeResponse {
  id: string;
  name: string;
  disabled?: boolean;
  comment?: string;
}

export interface BridgePortResponse {
  id: string;
  bridge: string;
  interface: string;
  disabled?: boolean;
  edge?: string;
  pathCost?: number;
  comment?: string;
}

export interface UpdateInterfaceBridgeRequest {
  interface: string;
  bridge: string;
}

export async function fetchBridges(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<BridgeResponse[]> {
  const list = await apiRequest<BridgeResponse[] | null>('/api/interface/bridges', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
  return list ?? [];
}

export async function fetchBridgePorts(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<BridgePortResponse[]> {
  const list = await apiRequest<BridgePortResponse[] | null>('/api/interface/bridge/ports', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
  return list ?? [];
}

export async function updateInterfaceBridge(
  creds: SystemCredentials,
  request: UpdateInterfaceBridgeRequest,
): Promise<void> {
  await apiRequest<unknown>('/api/interface/bridge/port', {
    method: 'PUT',
    headers: {
      ...authHeaders(creds),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });
}

export interface ForeignGatewayResponse {
  gateway: string | null;
}

export async function fetchForeignGateway(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<string | null> {
  const data = await apiRequest<ForeignGatewayResponse | null>('/api/route/foreign-gateway', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
  return data?.gateway ?? null;
}

export async function updateForeignGateway(
  creds: SystemCredentials,
  gateway: string,
  signal?: AbortSignal,
): Promise<void> {
  await apiRequest<unknown>('/api/route/foreign-gateway', {
    method: 'PUT',
    headers: {
      ...authHeaders(creds),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ gateway }),
    signal,
  });
}

export async function fetchVPNClients(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<VPNClientResponse[]> {
  const clients = await apiRequest<VPNClientResponse[] | null>('/api/vpn/clients', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
  return clients ?? [];
}

export async function setSystemIdentity(creds: SystemCredentials, name: string): Promise<void> {
  await apiRequest<void>('/api/system/identity', {
    method: 'PUT',
    headers: {
      ...authHeaders(creds),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ name }),
  });
}

export async function rebootSystem(creds: SystemCredentials): Promise<void> {
  await apiRequest<void>('/api/system/reboot', {
    method: 'POST',
    headers: authHeaders(creds),
  });
}

export async function changeUserPassword(
  creds: SystemCredentials,
  newPassword: string,
): Promise<void> {
  await apiRequest<void>('/api/system/password', {
    method: 'PUT',
    headers: {
      ...authHeaders(creds),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username: creds.username, newPassword }),
  });
}

export async function shutdownSystem(creds: SystemCredentials): Promise<void> {
  await apiRequest<void>('/api/system/shutdown', {
    method: 'POST',
    headers: authHeaders(creds),
  });
}

export async function fetchInterfaceGraph(
  creds: SystemCredentials,
  interfaceName: string,
  signal?: AbortSignal,
): Promise<InterfaceGraphResponse> {
  return apiRequest<InterfaceGraphResponse>(
    `/api/interface/graph/${encodeURIComponent(interfaceName)}`,
    {
      method: 'GET',
      headers: authHeaders(creds),
      cache: 'no-store',
      signal,
    },
  );
}

export type DynamicOverview = Pick<
  SystemOverview,
  | 'uptime'
  | 'cpuLoad'
  | 'cpuCount'
  | 'memoryUsedBytes'
  | 'memoryTotalBytes'
  | 'memoryUsedLabel'
  | 'memoryTotalLabel'
  | 'hddUsedBytes'
  | 'hddTotalBytes'
  | 'hddUsedLabel'
  | 'hddTotalLabel'
  | 'dhcpLeases'
  | 'vpnTunnels'
>;

/** The overview numbers, plus the lease and VPN client lists they were counted from. */
export async function fetchDynamicOverview(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<{
  overview: DynamicOverview;
  leases: DHCPLeaseResponse[];
  vpnClients: VPNClientResponse[];
}> {
  const [resources, leases, vpnClients] = await Promise.all([
    fetchSystemResources(creds, signal),
    fetchDHCPLeases(creds, signal).catch(() => [] as DHCPLeaseResponse[]),
    fetchVPNClients(creds, signal).catch(() => [] as VPNClientResponse[]),
  ]);
  const hddUsedBytes = Math.max(0, resources.hddTotalBytes - resources.hddFreeBytes);
  const overview: DynamicOverview = {
    uptime: resources.uptime,
    cpuLoad: resources.cpuLoad,
    cpuCount: resources.cpuCount,
    memoryUsedBytes: resources.memoryUsedBytes,
    memoryTotalBytes: resources.memoryTotalBytes,
    memoryUsedLabel: resources.memoryUsed,
    memoryTotalLabel: resources.memoryTotal,
    hddUsedBytes,
    hddTotalBytes: resources.hddTotalBytes,
    hddUsedLabel: formatBytes(hddUsedBytes),
    hddTotalLabel: resources.hddTotal,
    dhcpLeases: leases.length,
    vpnTunnels: vpnClients.length,
  };
  return { overview, leases, vpnClients };
}

export async function fetchSystemOverview(
  routerId: string,
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<SystemOverview> {
  const [info, { overview: dynamic }] = await Promise.all([
    fetchSystemInfo(creds, signal),
    fetchDynamicOverview(creds, signal),
  ]);

  return {
    routerId,
    identity: info.identity || 'unknown',
    model: info.boardName || 'unknown',
    version: info.version || 'unknown',
    buildTime: info.buildTime || '',
    updateChannel: info.updateChannel || '',
    license: info.license || '',
    serial: info.systemId || '',
    temperatureC: 0,
    interfaceCount: 0,
    ...dynamic,
  };
}

export interface VPNBypassState {
  enabled: boolean;
  /** VPN client the bypass returns to when turned off. */
  restoreTo?: string;
}

export async function fetchVPNBypass(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<VPNBypassState> {
  return apiRequest<VPNBypassState>('/api/route/vpn-bypass', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
}

export async function setVPNBypass(
  creds: SystemCredentials,
  enabled: boolean,
  signal?: AbortSignal,
): Promise<VPNBypassState> {
  return apiRequest<VPNBypassState>('/api/route/vpn-bypass', {
    method: 'PUT',
    headers: {
      ...authHeaders(creds),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ enabled }),
    signal,
  });
}

export interface ForeignSite {
  id: string;
  /** Domain, IPv4 address or range. */
  address: string;
  /** "vpn" for a site whose server is in Iran, so it never sees the Starlink IP. */
  route: 'starlink' | 'vpn';
  /** Its addresses on the Iranian IP list; the firewall keeps those off Starlink. */
  iranianIps?: string[];
}

export async function fetchForeignSites(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<ForeignSite[]> {
  return apiRequest<ForeignSite[]>('/api/route/foreign-sites', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
}

export async function addForeignSite(
  creds: SystemCredentials,
  address: string,
): Promise<ForeignSite[]> {
  return apiRequest<ForeignSite[]>('/api/route/foreign-sites', {
    method: 'POST',
    headers: { ...authHeaders(creds), 'Content-Type': 'application/json' },
    body: JSON.stringify({ address }),
  });
}

export async function removeForeignSite(
  creds: SystemCredentials,
  id: string,
): Promise<ForeignSite[]> {
  return apiRequest<ForeignSite[]>(`/api/route/foreign-sites/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: authHeaders(creds),
  });
}

export interface IranIPListState {
  entries: number;
  managedByPanel: boolean;
  updatedAt?: string;
  sources: string[];
}

export interface IranIPUpdateResult {
  total: number;
  added: number;
  removed: number;
  updatedAt: string;
}

export async function fetchIranIPList(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<IranIPListState> {
  return apiRequest<IranIPListState>('/api/route/iran-ip', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
}

export async function updateIranIPList(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<IranIPUpdateResult> {
  return apiRequest<IranIPUpdateResult>('/api/route/iran-ip/update', {
    method: 'POST',
    headers: authHeaders(creds),
    signal,
  });
}

export async function fetchDNSLeakGuard(
  creds: SystemCredentials,
  signal?: AbortSignal,
): Promise<{ enabled: boolean }> {
  return apiRequest<{ enabled: boolean }>('/api/dns/leak-guard', {
    method: 'GET',
    headers: authHeaders(creds),
    cache: 'no-store',
    signal,
  });
}

export async function setDNSLeakGuard(
  creds: SystemCredentials,
  enabled: boolean,
  signal?: AbortSignal,
): Promise<{ enabled: boolean }> {
  return apiRequest<{ enabled: boolean }>('/api/dns/leak-guard', {
    method: 'PUT',
    headers: {
      ...authHeaders(creds),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ enabled }),
    signal,
  });
}
