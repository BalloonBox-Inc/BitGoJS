import { register } from '../../../../src';
import { TransactionBuilderFactory } from '../../../../src/coin/near';
import should from 'should';
import * as testData from '../../../resources/near';
import * as nearAPI from 'near-api-js';
import BN from 'bn.js';
import { TransactionType } from '../../../../src/coin/baseCoin';

describe('Near Wallet Initialization Builder', () => {
  const factory = register('tnear', TransactionBuilderFactory);

  const walletInitBuilder = () => {
    const txBuilder = factory.getWalletInitializationBuilder();
    return txBuilder;
  };

  describe('Build and sign', () => {
    describe('Succeed', () => {
      it('build a wallet init tx unsigned', async () => {
        const txBuilder = walletInitBuilder();
        txBuilder.sender(testData.accounts.account1.address);
        txBuilder.nounce(1);
        txBuilder.publicKey(testData.accounts.account1.publicKey);
        txBuilder.receiverId(testData.accounts.account2.address);
        txBuilder.recentBlockHash(testData.blockHash.block1);
        const actions = [nearAPI.transactions.transfer(new BN(1))];
        txBuilder.actions(actions);
        const tx = await txBuilder.build();
        should.equal(tx.type, TransactionType.WalletInitialization);

        tx.inputs.length.should.equal(1);
        tx.inputs[0].should.deepEqual({
          address: testData.accounts.account1.address,
          value: '0.000000000000000000000001',
          coin: 'tnear',
        });
        tx.outputs.length.should.equal(1);
        tx.outputs[0].should.deepEqual({
          address: testData.accounts.account2.address,
          value: '0.000000000000000000000001',
          coin: 'tnear',
        });
        const rawTx = tx.toBroadcastFormat();
        should.equal(rawTx, testData.rawTx.transfer.unsigned);
      });

      it('build a wallet init tx and sign it', async () => {
        const txBuilder = walletInitBuilder();
        txBuilder.sender(testData.accounts.account1.address);
        txBuilder.nounce(1);
        txBuilder.publicKey(testData.accounts.account1.publicKey);
        txBuilder.receiverId(testData.accounts.account2.address);
        txBuilder.recentBlockHash(testData.blockHash.block1);
        const actions = [nearAPI.transactions.transfer(new BN(1))];
        txBuilder.actions(actions);
        txBuilder.sign({ key: testData.accounts.account1.secretKey });
        const tx = await txBuilder.build();
        should.equal(tx.type, TransactionType.WalletInitialization);

        tx.inputs.length.should.equal(1);
        tx.inputs[0].should.deepEqual({
          address: testData.accounts.account1.address,
          value: '0.000000000000000000000001',
          coin: 'tnear',
        });
        tx.outputs.length.should.equal(1);
        tx.outputs[0].should.deepEqual({
          address: testData.accounts.account2.address,
          value: '0.000000000000000000000001',
          coin: 'tnear',
        });
        const txBroadcast = tx.toBroadcastFormat();
        should.equal(txBroadcast, testData.rawTx.transfer.signed);
      });
    });
  });
});
