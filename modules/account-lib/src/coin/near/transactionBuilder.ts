import BigNumber from 'bignumber.js';
import { BaseCoin as CoinConfig } from '@bitgo/statics';
import { BaseTransactionBuilder } from '../baseCoin';
import { BuildTransactionError } from '../baseCoin/errors';
import { BaseAddress, BaseKey } from '../baseCoin/iface';
import { Transaction } from './transaction';
import * as nearAPI from 'near-api-js';
import { AddressValidationError } from '../dot/errors';
import utils from './utils';
import assert from 'assert';
import { KeyPair } from './keyPair';

export abstract class TransactionBuilder extends BaseTransactionBuilder {
  private _transaction: Transaction;

  private _sender: string;
  private _publicKey: string;
  private _receiverId: string;
  private _nonce: number;
  private _recentBlockHash: string;
  private _actions: nearAPI.transactions.Action[];
  private _signer: KeyPair;

  constructor(_coinConfig: Readonly<CoinConfig>) {
    super(_coinConfig);
    this._transaction = new Transaction(_coinConfig);
  }

  /**
   * Initialize the transaction builder fields using the decoded transaction data
   *
   * @param {Transaction} tx the transaction data
   */
  initBuilder(tx: Transaction): void {
    this._transaction = tx;
    const nearTransaction = tx.nearTransaction;
    this._sender = nearTransaction.signerId;
    this._nonce = nearTransaction.nonce;
    this._receiverId = nearTransaction.receiverId;
    this._publicKey = nearTransaction.publicKey.toString();
    this._recentBlockHash = nearAPI.utils.serialize.base_encode(nearTransaction.blockHash);
    this._actions = nearTransaction.actions;
  }

  /** @inheritdoc */
  protected fromImplementation(rawTransaction: string): Transaction {
    this.validateRawTransaction(rawTransaction);
    this.buildImplementation();
    return this.transaction;
  }

  /** @inheritdoc */
  protected async buildImplementation(): Promise<Transaction> {
    this.transaction.nearTransaction = this.buildNearTransaction();
    if (this._signer) {
      this.transaction.sign(this._signer);
    }
    this.transaction.buildInputAndOutput();
    return this.transaction;
  }

  /** @inheritdoc */
  protected signImplementation(key: BaseKey): Transaction {
    const prv = key.key;
    const signer = new KeyPair({ prv: prv });
    this._signer = signer;
    return this._transaction;
  }

  // region Getters and Setters
  /** @inheritdoc */
  protected get transaction(): Transaction {
    return this._transaction;
  }

  /** @inheritdoc */
  protected set transaction(transaction: Transaction) {
    this._transaction = transaction;
  }

  // endregion

  // region Validators
  /** @inheritdoc */
  validateAddress(address: BaseAddress, addressFormat?: string): void {
    if (!utils.isValidAddress(address.address)) {
      throw new AddressValidationError(address.address);
    }
  }

  /** @inheritdoc */
  validateKey(key: BaseKey): void {
    try {
      new KeyPair({ prv: key.key });
    } catch {
      throw new BuildTransactionError(`Key validation failed`);
    }
  }

  /** @inheritdoc */
  validateRawTransaction(rawTransaction: any): void {
    try {
      nearAPI.utils.serialize.deserialize(
        nearAPI.transactions.SCHEMA,
        nearAPI.transactions.SignedTransaction,
        rawTransaction,
      );
    } catch {
      try {
        nearAPI.utils.serialize.deserialize(
          nearAPI.transactions.SCHEMA,
          nearAPI.transactions.Transaction,
          rawTransaction,
        );
      } catch {
        throw new BuildTransactionError('invalid raw transaction');
      }
    }
  }

  /** @inheritdoc */
  validateTransaction(transaction: Transaction): void {
    if (!transaction.nearTransaction) {
      return;
    }
    this.validateAddress({ address: transaction.nearTransaction.signerId });
    this.validateAddress({ address: transaction.nearTransaction.receiverId });
  }

  /** @inheritdoc */
  validateValue(value: BigNumber): void {
    if (value.isLessThan(0)) {
      throw new BuildTransactionError('Value cannot be less than zero');
    }
  }

  // endregion

  public sender(value: string) {
    this._sender = value;
  }

  public receiverId(value: string) {
    this._receiverId = value;
  }

  public nounce(value: number) {
    this._nonce = value;
  }

  public recentBlockHash(value: string) {
    this._recentBlockHash = value;
  }

  public actions(value: nearAPI.transactions.Action[]) {
    this._actions = value;
  }

  public publicKey(value: string) {
    this._publicKey = value;
  }
  /**
   * Builds the NEAR transaction.
   */
  protected buildNearTransaction(): nearAPI.transactions.Transaction {
    assert(this._sender, new BuildTransactionError('sender is required before building'));
    assert(this._recentBlockHash, new BuildTransactionError('recent blockhash is required before building'));

    const publicKey = nearAPI.utils.PublicKey.fromString(
      nearAPI.utils.serialize.base_encode(Buffer.from(this._publicKey, 'hex')),
    );
    const blockHash = nearAPI.utils.serialize.base_decode(this._recentBlockHash);

    const tx = nearAPI.transactions.createTransaction(
      this._sender,
      publicKey,
      this._receiverId,
      this._nonce,
      this._actions,
      blockHash,
    );

    return tx;
  }
}
