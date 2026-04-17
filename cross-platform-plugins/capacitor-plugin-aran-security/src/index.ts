import { registerPlugin } from '@capacitor/core';

import type { AranSecurityPlugin } from './definitions';

const AranSecurity = registerPlugin<AranSecurityPlugin>('AranSecurity', {
  web: () => import('./web').then(m => new m.AranSecurityWeb()),
});

export * from './definitions';
export { AranSecurity };
