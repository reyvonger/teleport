/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import React from 'react';

import { ButtonBorder, ButtonPrimary, ButtonWithMenu, MenuItem } from 'design';
import {
  MenuItemSectionLabel,
  MenuItemSectionSeparator,
} from 'design/Menu/MenuItem';
import { App, PortRange } from 'gen-proto-ts/teleport/lib/teleterm/v1/app_pb';
import { Cluster } from 'gen-proto-ts/teleport/lib/teleterm/v1/cluster_pb';
import { Database } from 'gen-proto-ts/teleport/lib/teleterm/v1/database_pb';
import { Kube } from 'gen-proto-ts/teleport/lib/teleterm/v1/kube_pb';
import { Server } from 'gen-proto-ts/teleport/lib/teleterm/v1/server_pb';
import { WindowsDesktop } from 'gen-proto-ts/teleport/lib/teleterm/v1/windows_desktop_pb';
import { AwsLaunchButton } from 'shared/components/AwsLaunchButton';
import {
  MenuInputType,
  MenuLogin,
  MenuLoginProps,
} from 'shared/components/MenuLogin';
import { MenuLoginWithActionMenu } from 'shared/components/MenuLoginWithActionMenu';

import {
  formatPortRange,
  getAwsAppLaunchUrl,
  getSamlAppSsoUrl,
  getWebAppLaunchUrl,
  isWebApp,
} from 'teleterm/services/tshd/app';
import { GatewayProtocol } from 'teleterm/services/tshd/types';
import { appToAddrToCopy } from 'teleterm/services/vnet/app';
import { useAppContext } from 'teleterm/ui/appContextProvider';
import {
  captureAppLaunchInBrowser,
  connectToDatabase,
  connectToKube,
  connectToServer,
  connectToWindowsDesktop,
  setUpAppGateway,
} from 'teleterm/ui/services/workspacesService';
import { IAppContext } from 'teleterm/ui/types';
import { DatabaseUri, routing } from 'teleterm/ui/uri';
import { retryWithRelogin } from 'teleterm/ui/utils';
import { useVnetContext, useVnetLauncher } from 'teleterm/ui/Vnet';

export function ConnectServerActionButton(props: {
  server: Server;
}): React.JSX.Element {
  const ctx = useAppContext();
  const { isSupported: isVnetSupported } = useVnetContext();
  const { launchVnet } = useVnetLauncher();

  function connectWithVnet(): void {
    const hostname = props.server.hostname;
    const cluster = ctx.clustersService.findClusterByResource(props.server.uri);
    const clusterName = cluster?.name || '<cluster>';
    const addr = `${hostname}.${clusterName}`;
    launchVnet({
      addrToCopy: addr,
      resourceUri: props.server.uri,
    });
  }

  function getSshLogins(): string[] {
    const cluster = ctx.clustersService.findClusterByResource(props.server.uri);
    return cluster?.loggedInUser?.sshLogins || [];
  }

  function connect(login: string): void {
    const { uri, hostname } = props.server;
    connectToServer(
      ctx,
      { uri, hostname, login },
      {
        origin: 'resource_table',
      }
    );
  }

  const commonProps = {
    inputType: MenuInputType.FILTER,
    textTransform: 'none',
    getLoginItems: () => getSshLogins().map(login => ({ login, url: '' })),
    onSelect: (e, login) => connect(login),
    transformOrigin: {
      vertical: 'top',
      horizontal: 'right',
    },
    anchorOrigin: {
      vertical: 'bottom',
      horizontal: 'right',
    },
  };

  if (!isVnetSupported) {
    return <MenuLogin {...commonProps} />;
  }
  return (
    <MenuLoginWithActionMenu size="small" {...commonProps}>
      <MenuItem onClick={connectWithVnet}>Connect with VNet</MenuItem>
    </MenuLoginWithActionMenu>
  );
}

export function ConnectKubeActionButton(props: {
  kube: Kube;
}): React.JSX.Element {
  const appContext = useAppContext();

  function connect(): void {
    connectToKube(
      appContext,
      { uri: props.kube.uri },
      { origin: 'resource_table' }
    );
  }

  return (
    <ButtonBorder textTransform="none" size="small" onClick={connect}>
      Connect
    </ButtonBorder>
  );
}

export function ConnectAppActionButton(props: { app: App }): React.JSX.Element {
  const appContext = useAppContext();
  const { isSupported: isVnetSupported } = useVnetContext();
  const { launchVnet } = useVnetLauncher();

  function connectWithVnet(targetPort?: number): void {
    void launchVnet({
      addrToCopy: appToAddrToCopy(props.app, targetPort),
      resourceUri: props.app.uri,
      isMultiPortApp: !!props.app.tcpPorts.length,
    });
  }

  function setUpGateway(targetPort?: number): void {
    if (!targetPort && props.app.tcpPorts.length > 0) {
      targetPort = props.app.tcpPorts[0].port;
    }

    setUpAppGateway(appContext, props.app.uri, {
      telemetry: { origin: 'resource_table' },
      targetPort,
    });
  }

  const rootCluster = appContext.clustersService.findCluster(
    routing.ensureRootClusterUri(props.app.uri)
  );
  const cluster = appContext.clustersService.findClusterByResource(
    props.app.uri
  );

  return (
    <AppButton
      connectWithVnet={connectWithVnet}
      setUpGateway={setUpGateway}
      app={props.app}
      cluster={cluster}
      rootCluster={rootCluster}
      isVnetSupported={isVnetSupported}
      onLaunchUrl={() => {
        captureAppLaunchInBrowser(appContext, props.app, {
          origin: 'resource_table',
        });
      }}
    />
  );
}

export function ConnectDatabaseActionButton(props: {
  database: Database;
}): React.JSX.Element {
  const appContext = useAppContext();

  function connect(dbUser: string): void {
    const { uri, name, protocol } = props.database;
    connectToDatabase(
      appContext,
      { uri, name, protocol, dbUser },
      { origin: 'resource_table' }
    );
  }

  return (
    <MenuLogin
      {...getDatabaseMenuLoginOptions(
        props.database.protocol as GatewayProtocol
      )}
      textTransform="none"
      width="195px"
      getLoginItems={() => getDatabaseUsers(appContext, props.database.uri)}
      onSelect={(_, user) => {
        connect(user);
      }}
      transformOrigin={{
        vertical: 'top',
        horizontal: 'right',
      }}
      anchorOrigin={{
        vertical: 'bottom',
        horizontal: 'right',
      }}
    />
  );
}

function getDatabaseMenuLoginOptions(
  protocol: GatewayProtocol
): Pick<MenuLoginProps, 'placeholder' | 'required'> {
  if (protocol === 'redis') {
    return {
      placeholder: 'Enter username (optional)',
      required: false,
    };
  }

  return {
    placeholder: 'Enter username',
    required: true,
  };
}

async function getDatabaseUsers(appContext: IAppContext, dbUri: DatabaseUri) {
  try {
    const dbUsers = await retryWithRelogin(appContext, dbUri, () =>
      appContext.resourcesService.getDbUsers(dbUri)
    );
    return dbUsers.map(user => ({ login: user, url: '' }));
  } catch (e) {
    // Emitting a warning instead of an error here because fetching those username suggestions is
    // not the most important part of the app.
    appContext.notificationsService.notifyWarning({
      title: 'Could not fetch database usernames',
      description: e.message,
    });

    throw e;
  }
}

function AppButton(props: {
  app: App;
  cluster: Cluster;
  rootCluster: Cluster;
  connectWithVnet(targetPort?: number): void;
  setUpGateway(targetPort?: number): void;
  onLaunchUrl(): void;
  isVnetSupported: boolean;
}) {
  if (props.app.awsConsole) {
    return (
      <AwsLaunchButton
        awsRoles={props.app.awsRoles}
        getLaunchUrl={arn =>
          getAwsAppLaunchUrl({
            app: props.app,
            rootCluster: props.rootCluster,
            cluster: props.cluster,
            arn,
          })
        }
        onLaunchUrl={props.onLaunchUrl}
      />
    );
  }

  if (props.app.samlApp) {
    return (
      <ButtonBorder
        size="small"
        onClick={props.onLaunchUrl}
        as="a"
        textTransform="none"
        title="Log in to the SAML application in the browser"
        href={getSamlAppSsoUrl({
          app: props.app,
          rootCluster: props.rootCluster,
        })}
        target="_blank"
      >
        Log In
      </ButtonBorder>
    );
  }

  if (isWebApp(props.app)) {
    return (
      <ButtonWithMenu
        text="Launch"
        textTransform="none"
        size="small"
        forwardedAs="a"
        href={getWebAppLaunchUrl({
          app: props.app,
          rootCluster: props.rootCluster,
          cluster: props.cluster,
        })}
        onClick={props.onLaunchUrl}
        target="_blank"
        title="Launch the app in the browser"
      >
        <MenuItem onClick={() => props.setUpGateway()}>
          Set up connection
        </MenuItem>
      </ButtonWithMenu>
    );
  }

  // TCP app with VNet.
  if (props.isVnetSupported) {
    return (
      <ButtonWithMenu
        text="Connect"
        textTransform="none"
        size="small"
        onClick={() => props.connectWithVnet()}
      >
        <MenuItem onClick={() => props.setUpGateway()}>
          Connect without VNet
        </MenuItem>
        {!!props.app.tcpPorts.length && (
          <>
            <MenuItemSectionSeparator />
            <AvailableTargetPorts
              tcpPorts={props.app.tcpPorts}
              onItemClick={port => props.connectWithVnet(port)}
            />
          </>
        )}
      </ButtonWithMenu>
    );
  }

  // Multi-port TCP app without VNet.
  if (props.app.tcpPorts.length) {
    return (
      <ButtonWithMenu
        text="Connect"
        textTransform="none"
        size="small"
        onClick={() => props.setUpGateway()}
      >
        <AvailableTargetPorts
          tcpPorts={props.app.tcpPorts}
          onItemClick={port => props.setUpGateway(port)}
        />
      </ButtonWithMenu>
    );
  }

  // Single-port TCP app without VNet.
  return (
    <ButtonBorder
      size="small"
      onClick={() => props.setUpGateway()}
      textTransform="none"
    >
      Connect
    </ButtonBorder>
  );
}

const AvailableTargetPorts = (props: {
  tcpPorts: PortRange[];
  onItemClick: (portRangePort: number) => void;
}) => (
  <>
    <MenuItemSectionLabel>Available target ports</MenuItemSectionLabel>
    {props.tcpPorts.map((portRange, index) => (
      <MenuItem
        // This list can't be dynamically reordered, so index as key is fine. Port ranges are
        // not guaranteed to be unique, the user might add the same range twice.
        key={index}
        title="Start VNet and copy address to clipboard"
        // In case that portRange represents a range and not a single port, passing the first
        // port is fine. Otherwise we'd need to somehow offer an input for the user to choose
        // any port within the range.
        onClick={() => props.onItemClick(portRange.port)}
      >
        {formatPortRange(portRange)}
      </MenuItem>
    ))}
  </>
);

export function AccessRequestButton(props: {
  isResourceAdded: boolean;
  requestStarted: boolean;
  onClick(): void;
}) {
  return props.isResourceAdded ? (
    <ButtonPrimary
      textTransform="none"
      width="124px"
      size="small"
      onClick={props.onClick}
    >
      Remove
    </ButtonPrimary>
  ) : (
    <ButtonBorder
      textTransform="none"
      width="124px"
      size="small"
      onClick={props.onClick}
    >
      {props.requestStarted ? '+ Add to request' : '+ Request access'}
    </ButtonBorder>
  );
}

export function ConnectWindowsDesktopActionButton(props: {
  windowsDesktop: WindowsDesktop;
}): React.JSX.Element {
  const appContext = useAppContext();

  function connect(login: string): void {
    const { uri } = props.windowsDesktop;
    void connectToWindowsDesktop(
      appContext,
      { uri, login },
      { origin: 'resource_table' }
    );
  }

  return (
    <MenuLogin
      textTransform="none"
      width="195px"
      getLoginItems={() =>
        props.windowsDesktop.logins.map(l => ({ login: l, url: '' }))
      }
      onSelect={(_, user) => {
        connect(user);
      }}
      transformOrigin={{
        vertical: 'top',
        horizontal: 'right',
      }}
      anchorOrigin={{
        vertical: 'bottom',
        horizontal: 'right',
      }}
    />
  );
}
