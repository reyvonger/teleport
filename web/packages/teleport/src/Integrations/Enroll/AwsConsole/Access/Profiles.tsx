import { useEffect, useState } from 'react';

import { ButtonPrimary } from 'design/Button';
import { CardTile } from 'design/CardTile';
import Flex from 'design/Flex';
import * as Icons from 'design/Icon';
import { H3, P1, P2 } from 'design/Text';
import { Toggle } from 'design/Toggle';
import Validation from 'shared/components/Validation';

import { rolesAnywhereCreateProfile } from 'teleport/Integrations/Enroll/awsLinks';

import { ProfilesFilter } from './ProfilesFilter';
import { ProfilesTable } from './ProfilesTable';

export type Profile = {
  name: string;
  tags: string[];
  roles: string[];
};

export function Profiles({
  profiles,
  refresh,
}: {
  profiles: Profile[];
  refresh: () => void;
}) {
  const [syncAll, setSyncAll] = useState(true);
  const [selected, setSelected] = useState<Profile[]>(profiles);

  useEffect(() => {
    // todo mberg will actually call API and return all/set from response;
    // this use effect will go away
    if (syncAll) {
      setSelected(profiles);
    } else {
      setSelected([]);
    }
  }, [syncAll]);

  return (
    <Validation>
      <CardTile backgroundColor="levels.elevated">
        <Flex justifyContent="space-between">
          <Flex flexDirection="column">
            <H3>Sync IAM Profiles with Teleport as Resources</H3>
            <P2>
              You will be able to see the imported profiles on the Resources
              Page
            </P2>
          </Flex>
          <Flex alignItems="center" gap={3}>
            <ButtonPrimary
              gap={2}
              fill="minimal"
              intent="neutral"
              size="small"
              onClick={refresh}
            >
              <Icons.Refresh size="small" />
              Refresh
            </ButtonPrimary>
            <ButtonPrimary
              gap={2}
              intent="neutral"
              size="small"
              as="a"
              target="blank"
              href={rolesAnywhereCreateProfile}
            >
              Create AWS Roles Anywhere Profiles
              <Icons.NewTab size="small" />
            </ButtonPrimary>
            <Flex gap={1}>
              <Toggle
                isToggled={syncAll}
                onToggle={() => {
                  setSyncAll(!syncAll);
                }}
                size="large"
              />
              <P1>Import All Profiles</P1>
            </Flex>
          </Flex>
        </Flex>
        {!syncAll && <ProfilesFilter />}
        <ProfilesTable
          profiles={profiles}
          loading={false}
          selected={selected}
        />
      </CardTile>
    </Validation>
  );
}
