import should from 'should';
import sinon, { assert } from 'sinon';
import { BatchTransactionBuilder } from '../../../../../src/coin/dot';
import * as DotResources from '../../../../resources/dot';
import { buildTestConfig } from './base';
import { ProxyType } from '../../../../../src/coin/dot/iface';

describe('Dot Batch Transaction Builder', () => {
  let builder: BatchTransactionBuilder;

  const specVersion = 9150;
  const referenceBlock = '0x462ab5246361febb9294ffa41dd099edddec30a205ea15fbd247abb0ddbabd51';
  const sender = DotResources.accounts.account1;

  beforeEach(() => {
    const config = buildTestConfig();
    builder = new BatchTransactionBuilder(config);
  });

  describe('setter validation', () => {
    it('should validate list of calls', () => {
      const call = 'invalidUnsignedTransaction';
      const spy = sinon.spy(builder, 'validateCalls');
      should.throws(
        () => builder.calls([call]),
        (e: Error) => e.message === `call in string format must be hex format of a method and its arguments`,
      );
      should.doesNotThrow(() => builder.calls(DotResources.rawTx.anonymous.batch));
      assert.calledTwice(spy);
    });
  });

  describe('build batch transaction', () => {
    it('should build a batch transaction', async () => {
      builder
        .calls(DotResources.rawTx.anonymous.batch)
        .sender({ address: sender.address })
        .validity({ firstValid: 9279281, maxDuration: 64 })
        .referenceBlock(referenceBlock)
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 0 })
        .fee({ amount: 0, type: 'tip' })
        .version(8);
      builder.sign({ key: sender.secretKey });
      const tx = await builder.build();
      const txJson = tx.toJson();
      should.deepEqual(txJson.batchCalls.length, DotResources.rawTx.anonymous.batch.length);
      should.deepEqual(txJson.batchCalls[0].callIndex, DotResources.rawTx.anonymous.batch[0].slice(0, 6));
      should.deepEqual(txJson.batchCalls[0].args?.proxy_type, ProxyType.ANY);
      should.deepEqual(txJson.batchCalls[0].args?.delay, 0);
      should.deepEqual(txJson.batchCalls[0].args?.index, 0);
      should.deepEqual(txJson.batchCalls[1].callIndex, DotResources.rawTx.anonymous.batch[0].slice(0, 6));
      should.deepEqual(txJson.batchCalls[1].args?.proxy_type, ProxyType.ANY);
      should.deepEqual(txJson.batchCalls[1].args?.delay, 0);
      should.deepEqual(txJson.batchCalls[1].args?.index, 1);
      should.deepEqual(txJson.sender, sender.address);
      should.deepEqual(txJson.blockNumber, 9279281);
      should.deepEqual(txJson.referenceBlock, referenceBlock);
      should.deepEqual(txJson.genesisHash, '0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e');
      should.deepEqual(txJson.specVersion, specVersion);
      should.deepEqual(txJson.nonce, 0);
      should.deepEqual(txJson.tip, 0);
      should.deepEqual(txJson.transactionVersion, 8);
      should.deepEqual(txJson.chainName, 'Westend');
      should.deepEqual(txJson.eraPeriod, 64);
    });
    it('should build an unsigned batch transaction', async () => {
      builder
        .calls(DotResources.rawTx.anonymous.batch)
        .sender({ address: sender.address })
        .validity({ firstValid: 9266787, maxDuration: 64 })
        .referenceBlock(referenceBlock)
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 200 })
        .fee({ amount: 0, type: 'tip' })
        .version(8);
      const tx = await builder.build();
      const txJson = tx.toJson();
      should.deepEqual(txJson.batchCalls.length, DotResources.rawTx.anonymous.batch.length);
      should.deepEqual(txJson.batchCalls[0].callIndex, DotResources.rawTx.anonymous.batch[0].slice(0, 6));
      should.deepEqual(txJson.batchCalls[0].args?.proxy_type, ProxyType.ANY);
      should.deepEqual(txJson.batchCalls[0].args?.delay, 0);
      should.deepEqual(txJson.batchCalls[0].args?.index, 0);
      should.deepEqual(txJson.batchCalls[1].callIndex, DotResources.rawTx.anonymous.batch[0].slice(0, 6));
      should.deepEqual(txJson.batchCalls[1].args?.proxy_type, ProxyType.ANY);
      should.deepEqual(txJson.batchCalls[1].args?.delay, 0);
      should.deepEqual(txJson.batchCalls[1].args?.index, 1);
      should.deepEqual(txJson.sender, sender.address);
      should.deepEqual(txJson.blockNumber, 9266787);
      should.deepEqual(txJson.referenceBlock, referenceBlock);
      should.deepEqual(txJson.genesisHash, '0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e');
      should.deepEqual(txJson.specVersion, specVersion);
      should.deepEqual(txJson.nonce, 200);
      should.deepEqual(txJson.tip, 0);
      should.deepEqual(txJson.transactionVersion, 8);
      should.deepEqual(txJson.chainName, 'Westend');
      should.deepEqual(txJson.eraPeriod, 64);
    });
    it('should build from raw signed tx', async () => {
      builder.from(DotResources.rawTx.batch.signed);
      builder.validity({ firstValid: 9266787, maxDuration: 64 }).referenceBlock(referenceBlock).version(8);
      const tx = await builder.build();
      const txJson = tx.toJson();
      // test the call items
      should.deepEqual(txJson.sender, sender.address);
      should.deepEqual(txJson.batchCalls.length, 3);
      should.deepEqual(txJson.batchCalls[0].args?.proxy_type, ProxyType.ANY);
      should.deepEqual(txJson.batchCalls[0].args?.delay, 0);
      should.deepEqual(txJson.batchCalls[0].args?.index, 0);
      should.deepEqual(txJson.batchCalls[1].args?.proxy_type, ProxyType.ANY);
      should.deepEqual(txJson.batchCalls[1].args?.delay, 0);
      should.deepEqual(txJson.batchCalls[1].args?.index, 1);
      should.deepEqual(txJson.batchCalls[2].args?.proxy_type, ProxyType.ANY);
      should.deepEqual(txJson.batchCalls[2].args?.delay, 0);
      should.deepEqual(txJson.batchCalls[2].args?.index, 2);
      should.deepEqual(txJson.blockNumber, 9266787);
      should.deepEqual(txJson.referenceBlock, referenceBlock);
      should.deepEqual(txJson.genesisHash, '0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e');
      should.deepEqual(txJson.specVersion, specVersion);
      should.deepEqual(txJson.nonce, 0);
      should.deepEqual(txJson.tip, 0);
      should.deepEqual(txJson.transactionVersion, 8);
      should.deepEqual(txJson.chainName, 'Westend');
      should.deepEqual(txJson.eraPeriod, 64);
    });
    it('should build from raw unsigned tx', async () => {
      builder.from(DotResources.rawTx.batch.unsigned);
      builder
        .validity({ firstValid: 9266787, maxDuration: 64 })
        .referenceBlock(referenceBlock)
        .sender({ address: sender.address })
        .sign({ key: sender.secretKey });
      const tx = await builder.build();
      const txJson = tx.toJson();
      should.deepEqual(txJson.sender, sender.address);
      should.deepEqual(txJson.batchCalls.length, 3);
      should.deepEqual(txJson.batchCalls[0].args?.proxy_type, ProxyType.ANY);
      should.deepEqual(txJson.batchCalls[0].args?.delay, 0);
      should.deepEqual(txJson.batchCalls[0].args?.index, 0);
      should.deepEqual(txJson.batchCalls[1].args?.proxy_type, ProxyType.ANY);
      should.deepEqual(txJson.batchCalls[1].args?.delay, 0);
      should.deepEqual(txJson.batchCalls[1].args?.index, 1);
      should.deepEqual(txJson.batchCalls[2].args?.proxy_type, ProxyType.ANY);
      should.deepEqual(txJson.batchCalls[2].args?.delay, 0);
      should.deepEqual(txJson.batchCalls[2].args?.index, 2);
      should.deepEqual(txJson.blockNumber, 9266787);
      should.deepEqual(txJson.referenceBlock, referenceBlock);
      should.deepEqual(txJson.genesisHash, '0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e');
      should.deepEqual(txJson.specVersion, specVersion);
      should.deepEqual(txJson.nonce, 0);
      should.deepEqual(txJson.tip, 0);
      should.deepEqual(txJson.transactionVersion, 8);
      should.deepEqual(txJson.chainName, 'Westend');
      should.deepEqual(txJson.eraPeriod, 64);
    });
  });
});
