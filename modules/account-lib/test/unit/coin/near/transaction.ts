import { coins } from '@bitgo/statics';
import should from 'should';
import { Transaction } from '../../../../src/coin/near';
import * as NearResources from '../../../resources/near';

describe('Near Transaction', () => {
  let tx: Transaction;
  const config = coins.get('tnear');

  beforeEach(() => {
    tx = new Transaction(config);
  });

  describe('empty transaction', () => {
    it('should throw empty transaction', () => {
      should.throws(() => tx.toJson(), 'Empty transaction');
      should.throws(() => tx.toBroadcastFormat(), 'Empty transaction');
    });
  });

  describe('sign transaction', () => {
    it('can sign', () => {
      should.deepEqual(tx.canSign({ key: NearResources.accounts.account2.secretKey }), true);
    });
  });
});
