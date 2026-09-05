import tap from 'tap';
import { join } from 'path';
import { rm } from 'fs/promises';
import { tmpdir } from 'os';

import DB from '../../src/db/db';

tap.test('store take is an atomic one-winner operation', async (t) => {
  const db = await DB.new({ db: { engine: 'mem' }, logger: console }, true);
  const store = db.store('atomic-take');
  const value = { kind: 'authorization-code' };
  await store.put('one-use', value);

  const results = await Promise.all(Array.from({ length: 20 }, () => store.take('one-use')));
  t.equal(results.filter((result) => result !== null).length, 1);
  t.same(
    results.find((result) => result !== null),
    value
  );
  t.equal(await store.get('one-use'), null);
  await db.close();
});

tap.test('expired values cannot be taken', async (t) => {
  const db = await DB.new({ db: { engine: 'mem' }, logger: console }, true);
  const store = db.store('expiring-take', 0.02);
  await store.put('short-lived', { kind: 'authorization-code' });

  await new Promise((resolve) => setTimeout(resolve, 100));

  t.equal(await store.take('short-lived'), null);
  await db.close();
});

tap.test('SQLite take is atomic and does not delete a replacement', async (t) => {
  const databasePath = join(tmpdir(), `polis-atomic-take-${process.pid}-${Date.now()}.db`);
  const db = await DB.new(
    {
      db: {
        engine: 'sql',
        type: 'sqlite',
        url: databasePath,
        pageLimit: 20,
      },
      logger: console,
    },
    true
  );
  const store = db.store('sqlite-take');
  const original = { version: 1 };
  await store.put('concurrent', original);
  const claims = await Promise.all(Array.from({ length: 20 }, () => store.take('concurrent')));
  t.equal(claims.filter((claim) => claim !== null).length, 1);
  t.same(
    claims.find((claim) => claim !== null),
    original
  );

  await store.put('replaced', original);
  const sqlDriver = (db as any).db;
  const originalDelete = sqlDriver.storeRepository.delete.bind(sqlDriver.storeRepository);
  sqlDriver.storeRepository.delete = async (criteria: unknown) => {
    sqlDriver.storeRepository.delete = originalDelete;
    await store.put('replaced', { version: 2 });
    return originalDelete(criteria);
  };

  t.equal(await store.take('replaced'), null, 'stale reader loses the claim');
  t.same(await store.get('replaced'), { version: 2 }, 'replacement remains available');

  await db.close();
  await rm(databasePath, { force: true });
});

tap.test(
  'PostgreSQL take is atomic across independent connections and rejects expiry',
  { skip: !process.env.POLIS_TEST_POSTGRES_URL },
  async (t) => {
    const options = {
      db: {
        engine: 'sql' as const,
        type: 'postgres' as const,
        url: process.env.POLIS_TEST_POSTGRES_URL,
        pageLimit: 20,
      },
      logger: console,
    };
    const firstDb = await DB.new(options, true);
    const secondDb = await DB.new(options, true);
    const namespace = `postgres-take-${process.pid}-${Date.now()}`;
    const firstStore = firstDb.store(namespace);
    const secondStore = secondDb.store(namespace);

    await firstStore.put('concurrent', { version: 1 });
    const claims = await Promise.all([firstStore.take('concurrent'), secondStore.take('concurrent')]);
    t.equal(claims.filter((claim) => claim !== null).length, 1);
    t.same(
      claims.find((claim) => claim !== null),
      { version: 1 }
    );

    const expiringStore = firstDb.store(namespace, 0.02);
    await expiringStore.put('expired', { version: 2 });
    await new Promise((resolve) => setTimeout(resolve, 100));
    t.equal(await secondDb.store(namespace).take('expired'), null);

    await firstDb.close();
    await secondDb.close();
  }
);

tap.test('store take fails closed for a custom driver without atomic support', async (t) => {
  const unsupported = {
    get: async () => null,
    getAll: async () => ({ data: [] }),
    getByIndex: async () => ({ data: [] }),
    put: async () => undefined,
    delete: async () => undefined,
    deleteMany: async () => undefined,
    close: async () => undefined,
    getStats: () => ({}),
  };
  const db = await DB.new({ db: { driver: unsupported }, logger: console }, true);
  const store = db.store('unsupported-take');

  await t.rejects(store.take('code'), { message: 'Database driver does not support atomic take' });
  await db.close();
});
