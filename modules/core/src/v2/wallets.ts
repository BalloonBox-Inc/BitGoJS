/**
 * @prettier
 */
import * as bip32 from 'bip32';
import * as bs58 from 'bs58';
import { BitGo } from '../bitgo';
import * as common from '../common';
import * as crypto from 'crypto';
import { BaseCoin, KeychainsTriplet, SupplementGenerateWalletOptions } from './baseCoin';
import { RequestTracer as IRequestTracer } from './types';
import { PaginationOptions, Wallet } from './wallet';
import * as _ from 'lodash';
import { RequestTracer } from './internal/util';
import { sanitizeLegacyPath } from '../bip32path';
import { getSharedSecret } from '../ecdh';
import { BigNumber } from 'bignumber.js';
import { promiseProps } from './promise-utils';
import Eddsa, { KeyShare } from '@bitgo/account-lib/dist/src/mpc/tss';
import * as openpgp from 'openpgp';
import { Keychain } from './keychains';

export interface WalletWithKeychains extends KeychainsTriplet {
  wallet: Wallet;
  warning?: string;
}

export interface GetWalletOptions {
  allTokens?: boolean;
  reqId?: IRequestTracer;
  id?: string;
}

export interface GenerateWalletOptions {
  label?: string;
  passphrase?: string;
  userKey?: string;
  backupXpub?: string;
  backupXpubProvider?: string;
  passcodeEncryptionCode?: string;
  enterprise?: string;
  disableTransactionNotifications?: string;
  gasPrice?: string;
  eip1559?: {
    maxFeePerGas: string;
    maxPriorityFeePerGas: string;
  };
  walletVersion?: number;
  disableKRSEmail?: boolean;
  krsSpecific?: {
    [index: string]: boolean | string | number;
  };
  coldDerivationSeed?: string;
  rootPrivateKey?: string;
}

export interface GetWalletByAddressOptions {
  address?: string;
  reqId?: RequestTracer;
}

export interface UpdateShareOptions {
  walletShareId?: string;
  state?: string;
  encryptedPrv?: string;
}

export interface AcceptShareOptions {
  overrideEncryptedPrv?: string;
  walletShareId?: string;
  userPassword?: string;
  newWalletPassphrase?: string;
}

export interface AddWalletOptions {
  type?: string;
  keys?: string[];
  m?: number;
  n?: number;
  tags?: string[];
  clientFlags?: string[];
  isCold?: boolean;
  isCustodial?: boolean;
  address?: string;
  rootPub?: string;
  rootPrivateKey?: string;
  initializationTxs?: any;
  disableTransactionNotifications?: boolean;
  gasPrice?: number;
  walletVersion?: number;
}

export interface ListWalletOptions extends PaginationOptions {
  skip?: number;
  getbalances?: boolean;
  allTokens?: boolean;
}

export class Wallets {
  private readonly bitgo: BitGo;
  private readonly baseCoin: BaseCoin;

  constructor(bitgo: BitGo, baseCoin: BaseCoin) {
    this.bitgo = bitgo;
    this.baseCoin = baseCoin;
  }

  /**
   * Get a wallet by ID (proxy for getWallet)
   * @param params
   */
  async get(params: GetWalletOptions = {}): Promise<Wallet> {
    return this.getWallet(params);
  }

  /**
   * List a user's wallets
   * @param params
   * @returns {*}
   */
  async list(params: ListWalletOptions = {}): Promise<{ wallets: Wallet[] }> {
    const queryObject: ListWalletOptions = {};

    if (params.skip && params.prevId) {
      throw new Error('cannot specify both skip and prevId');
    }

    if (params.getbalances) {
      if (!_.isBoolean(params.getbalances)) {
        throw new Error('invalid getbalances argument, expecting boolean');
      }
      queryObject.getbalances = params.getbalances;
    }
    if (params.prevId) {
      if (!_.isString(params.prevId)) {
        throw new Error('invalid prevId argument, expecting string');
      }
      queryObject.prevId = params.prevId;
    }
    if (params.limit) {
      if (!_.isNumber(params.limit)) {
        throw new Error('invalid limit argument, expecting number');
      }
      queryObject.limit = params.limit;
    }

    if (params.allTokens) {
      if (!_.isBoolean(params.allTokens)) {
        throw new Error('invalid allTokens argument, expecting boolean');
      }
      queryObject.allTokens = params.allTokens;
    }

    const body = (await this.bitgo.get(this.baseCoin.url('/wallet')).query(queryObject).result()) as any;
    body.wallets = body.wallets.map((w) => new Wallet(this.bitgo, this.baseCoin, w));
    return body;
  }

  /**
   * add
   * Add a new wallet (advanced mode).
   * This allows you to manually submit the keys, type, m and n of the wallet
   * Parameters include:
   *    "label": label of the wallet to be shown in UI
   *    "m": number of keys required to unlock wallet (2)
   *    "n": number of keys available on the wallet (3)
   *    "keys": array of keychain ids
   */
  async add(params: AddWalletOptions = {}): Promise<any> {
    common.validateParams(params, [], ['label', 'enterprise', 'type']);

    // no need to pass keys for (single) custodial wallets
    if (params.type !== 'custodial') {
      if (Array.isArray(params.keys) === false || !_.isNumber(params.m) || !_.isNumber(params.n)) {
        throw new Error('invalid argument');
      }

      // TODO: support more types of multisig
      if (!this.baseCoin.isValidMofNSetup(params)) {
        throw new Error('unsupported multi-sig type');
      }
    }

    if (params.gasPrice && !_.isNumber(params.gasPrice)) {
      throw new Error('invalid argument for gasPrice - number expected');
    }

    if (params.walletVersion && !_.isNumber(params.walletVersion)) {
      throw new Error('invalid argument for walletVersion - number expected');
    }

    if (params.tags && Array.isArray(params.tags) === false) {
      throw new Error('invalid argument for tags - array expected');
    }

    if (params.clientFlags && Array.isArray(params.clientFlags) === false) {
      throw new Error('invalid argument for clientFlags - array expected');
    }

    if (params.isCold && !_.isBoolean(params.isCold)) {
      throw new Error('invalid argument for isCold - boolean expected');
    }

    if (params.isCustodial && !_.isBoolean(params.isCustodial)) {
      throw new Error('invalid argument for isCustodial - boolean expected');
    }

    if (params.address && (!_.isString(params.address) || !this.baseCoin.isValidAddress(params.address))) {
      throw new Error('invalid argument for address - valid address string expected');
    }

    const walletParams = _.pick(params, [
      'label',
      'm',
      'n',
      'keys',
      'enterprise',
      'isCold',
      'isCustodial',
      'tags',
      'clientFlags',
      'type',
      'address',
      'gasPrice',
      'walletVersion',
    ]);

    // Additional params needed for xrp
    if (params.rootPub) {
      walletParams.rootPub = params.rootPub;
    }

    // In XRP, XLM and CSPR this private key is used only for wallet creation purposes,
    // once the wallet is initialized then we update its weight to 0 making it an invalid key.
    // https://www.stellar.org/developers/guides/concepts/multi-sig.html#additional-signing-keys
    if (params.rootPrivateKey) {
      walletParams.rootPrivateKey = params.rootPrivateKey;
    }

    if (params.initializationTxs) {
      walletParams.initializationTxs = params.initializationTxs;
    }

    if (params.disableTransactionNotifications) {
      walletParams.disableTransactionNotifications = params.disableTransactionNotifications;
    }

    const newWallet = await this.bitgo.post(this.baseCoin.url('/wallet')).send(walletParams).result();
    return {
      wallet: new Wallet(this.bitgo, this.baseCoin, newWallet),
    };
  }

  /**
   * Generate a new wallet
   * 1. Creates the user keychain locally on the client, and encrypts it with the provided passphrase
   * 2. If no pub was provided, creates the backup keychain locally on the client, and encrypts it with the provided passphrase
   * 3. Uploads the encrypted user and backup keychains to BitGo
   * 4. Creates the BitGo key on the service
   * 5. Creates the wallet on BitGo with the 3 public keys above
   * @param params
   * @param params.label
   * @param params.passphrase
   * @param params.userKey User xpub
   * @param params.backupXpub Backup xpub
   * @param params.backupXpubProvider
   * @param params.enterprise
   * @param params.disableTransactionNotifications
   * @param params.passcodeEncryptionCode
   * @param params.coldDerivationSeed
   * @param params.gasPrice
   * @param params.disableKRSEmail
   * @param params.walletVersion
   * @returns {*}
   */
  async generateWallet(params: GenerateWalletOptions = {}): Promise<WalletWithKeychains> {
    common.validateParams(params, ['label'], ['passphrase', 'userKey', 'backupXpub']);
    if (!_.isString(params.label)) {
      throw new Error('missing required string parameter label');
    }
    const label = params.label;
    const passphrase = params.passphrase;
    const canEncrypt = !!passphrase && typeof passphrase === 'string';
    const isCold = !canEncrypt || !!params.userKey;

    const walletParams: SupplementGenerateWalletOptions = {
      label: label,
      m: 2,
      n: 3,
      keys: [],
      isCold,
    };

    const hasBackupXpub = !!params.backupXpub;
    const hasBackupXpubProvider = !!params.backupXpubProvider;
    if (hasBackupXpub && hasBackupXpubProvider) {
      throw new Error('Cannot provide more than one backupXpub or backupXpubProvider flag');
    }

    if (!_.isUndefined(params.passcodeEncryptionCode)) {
      if (!_.isString(params.passcodeEncryptionCode)) {
        throw new Error('passcodeEncryptionCode must be a string');
      }
    }

    if (params.gasPrice && params.eip1559) {
      throw new Error('can not use both eip1559 and gasPrice values');
    }

    if (!_.isUndefined(params.enterprise)) {
      if (!_.isString(params.enterprise)) {
        throw new Error('invalid enterprise argument, expecting string');
      }
      walletParams.enterprise = params.enterprise;
    }

    if (!_.isUndefined(params.disableTransactionNotifications)) {
      if (!_.isBoolean(params.disableTransactionNotifications)) {
        throw new Error('invalid disableTransactionNotifications argument, expecting boolean');
      }
      walletParams.disableTransactionNotifications = params.disableTransactionNotifications;
    }

    if (!_.isUndefined(params.gasPrice)) {
      const gasPriceBN = new BigNumber(params.gasPrice);
      if (gasPriceBN.isNaN()) {
        throw new Error('invalid gas price argument, expecting number or number as string');
      }
      walletParams.gasPrice = gasPriceBN.toString();
    }

    if (!_.isUndefined(params.eip1559) && !_.isEmpty(params.eip1559)) {
      const maxFeePerGasBN = new BigNumber(params.eip1559.maxFeePerGas);
      if (maxFeePerGasBN.isNaN()) {
        throw new Error('invalid max fee argument, expecting number or number as string');
      }
      const maxPriorityFeePerGasBN = new BigNumber(params.eip1559.maxPriorityFeePerGas);
      if (maxPriorityFeePerGasBN.isNaN()) {
        throw new Error('invalid priority fee argument, expecting number or number as string');
      }
      walletParams.eip1559 = {
        maxFeePerGas: maxFeePerGasBN.toString(),
        maxPriorityFeePerGas: maxPriorityFeePerGasBN.toString(),
      };
    }

    if (!_.isUndefined(params.disableKRSEmail)) {
      if (!_.isBoolean(params.disableKRSEmail)) {
        throw new Error('invalid disableKRSEmail argument, expecting boolean');
      }
      walletParams.disableKRSEmail = params.disableKRSEmail;
    }

    if (!_.isUndefined(params.walletVersion)) {
      if (!_.isNumber(params.walletVersion)) {
        throw new Error('invalid walletVersion provided, expecting number');
      }
      walletParams.walletVersion = params.walletVersion;
    }

    // Ensure each krsSpecific param is either a string, boolean, or number
    const { krsSpecific } = params;
    if (!_.isUndefined(krsSpecific)) {
      Object.keys(krsSpecific).forEach((key) => {
        const val = krsSpecific[key];
        if (!_.isBoolean(val) && !_.isString(val) && !_.isNumber(val)) {
          throw new Error('krsSpecific object contains illegal values. values must be strings, booleans, or numbers');
        }
      });
    }

    let derivationPath: string | undefined = undefined;

    const reqId = new RequestTracer();

    // Add the user keychain
    const userKeychainPromise = async (): Promise<any> => {
      let userKeychainParams;
      let userKeychain;
      // User provided user key
      if (params.userKey) {
        userKeychain = { pub: params.userKey };
        userKeychainParams = userKeychain;
        if (params.coldDerivationSeed) {
          // the derivation only makes sense when a key already exists
          const derivation = this.baseCoin.deriveKeyWithSeed({
            key: params.userKey,
            seed: params.coldDerivationSeed,
          });
          derivationPath = derivation.derivationPath;
          userKeychain.pub = derivation.key;
          userKeychain.derivedFromParentWithSeed = params.coldDerivationSeed;
        }
      } else {
        if (!canEncrypt) {
          throw new Error('cannot generate user keypair without passphrase');
        }
        // Create the user key.
        userKeychain = this.baseCoin.keychains().create();
        userKeychain.encryptedPrv = this.bitgo.encrypt({ password: passphrase, input: userKeychain.prv });
        userKeychainParams = {
          pub: userKeychain.pub,
          encryptedPrv: userKeychain.encryptedPrv,
          originalPasscodeEncryptionCode: params.passcodeEncryptionCode,
        };
      }

      userKeychainParams.reqId = reqId;
      const newUserKeychain = await this.baseCoin.keychains().add(userKeychainParams);
      return _.extend({}, newUserKeychain, userKeychain);
    };

    const backupKeychainPromise = async (): Promise<any> => {
      if (params.backupXpubProvider) {
        // If requested, use a KRS or backup key provider
        return this.baseCoin.keychains().createBackup({
          provider: params.backupXpubProvider || 'defaultRMGBackupProvider',
          disableKRSEmail: params.disableKRSEmail,
          krsSpecific: params.krsSpecific,
          type: this.baseCoin.getChain(),
          reqId,
        });
      }

      // User provided backup xpub
      if (params.backupXpub) {
        // user provided backup ethereum address
        return this.baseCoin.keychains().add({
          pub: params.backupXpub,
          source: 'backup',
          reqId,
        });
      } else {
        if (!canEncrypt) {
          throw new Error('cannot generate backup keypair without passphrase');
        }
        // No provided backup xpub or address, so default to creating one here
        return this.baseCoin.keychains().createBackup({ reqId });
      }
    };

    const { userKeychain, backupKeychain, bitgoKeychain }: KeychainsTriplet = await promiseProps({
      userKeychain: userKeychainPromise(),
      backupKeychain: backupKeychainPromise(),
      bitgoKeychain: this.baseCoin.keychains().createBitGo({ enterprise: params.enterprise, reqId }),
    });

    walletParams.keys = [userKeychain.id, backupKeychain.id, bitgoKeychain.id];

    walletParams.isCold = isCold;

    const { prv } = userKeychain;
    if (_.isString(prv)) {
      walletParams.keySignatures = {
        backup: (await this.baseCoin.signMessage({ prv }, backupKeychain.pub)).toString('hex'),
        bitgo: (await this.baseCoin.signMessage({ prv }, bitgoKeychain.pub)).toString('hex'),
      };
    }

    if (_.includes(['xrp', 'xlm', 'cspr'], this.baseCoin.getFamily()) && !_.isUndefined(params.rootPrivateKey)) {
      walletParams.rootPrivateKey = params.rootPrivateKey;
    }

    const keychains = {
      userKeychain,
      backupKeychain,
      bitgoKeychain,
    };
    const finalWalletParams = await this.baseCoin.supplementGenerateWallet(walletParams, keychains);
    this.bitgo.setRequestTracer(reqId);
    const newWallet = await this.bitgo.post(this.baseCoin.url('/wallet')).send(finalWalletParams).result();

    const result: WalletWithKeychains = {
      wallet: new Wallet(this.bitgo, this.baseCoin, newWallet),
      userKeychain: userKeychain,
      backupKeychain: backupKeychain,
      bitgoKeychain: bitgoKeychain,
    };

    if (!_.isUndefined(backupKeychain.prv)) {
      result.warning = 'Be sure to backup the backup keychain -- it is not stored anywhere else!';
    }

    if (!_.isUndefined(derivationPath)) {
      userKeychain.derivationPath = derivationPath;
    }

    return result;
  }

  /**
   * List the user's wallet shares
   * @param params
   */
  async listShares(params: Record<string, unknown> = {}): Promise<any> {
    return await this.bitgo.get(this.baseCoin.url('/walletshare')).result();
  }

  /**
   * Gets a wallet share information, including the encrypted sharing keychain. requires unlock if keychain is present.
   * @param params
   * @param params.walletShareId - the wallet share to get information on
   */
  async getShare(params: { walletShareId?: string } = {}): Promise<any> {
    common.validateParams(params, ['walletShareId'], []);

    return await this.bitgo.get(this.baseCoin.url('/walletshare/' + params.walletShareId)).result();
  }

  /**
   * Update a wallet share
   * @param params.walletShareId - the wallet share to update
   * @param params.state - the new state of the wallet share
   * @param params
   */
  async updateShare(params: UpdateShareOptions = {}): Promise<any> {
    common.validateParams(params, ['walletShareId'], []);

    return await this.bitgo
      .post(this.baseCoin.url('/walletshare/' + params.walletShareId))
      .send(params)
      .result();
  }

  /**
   * Resend a wallet share invitation email
   * @param params
   * @param params.walletShareId - the wallet share whose invitiation should be resent
   */
  async resendShareInvite(params: { walletShareId?: string } = {}): Promise<any> {
    common.validateParams(params, ['walletShareId'], []);

    const urlParts = params.walletShareId + '/resendemail';
    return this.bitgo.post(this.baseCoin.url('/walletshare/' + urlParts)).result();
  }

  /**
   * Cancel a wallet share
   * @param params
   * @param params.walletShareId - the wallet share to update
   */
  async cancelShare(params: { walletShareId?: string } = {}): Promise<any> {
    common.validateParams(params, ['walletShareId'], []);

    return await this.bitgo
      .del(this.baseCoin.url('/walletshare/' + params.walletShareId))
      .send()
      .result();
  }

  /**
   * Accepts a wallet share, adding the wallet to the user's list
   * Needs a user's password to decrypt the shared key
   *
   * @param params
   * @param params.walletShareId - the wallet share to accept
   * @param params.userPassword - (required if more a keychain was shared) user's password to decrypt the shared wallet
   * @param params.newWalletPassphrase - new wallet passphrase for saving the shared wallet prv.
   *                                     If left blank and a wallet with more than view permissions was shared,
   *                                     then the user's login password is used.
   * @param params.overrideEncryptedPrv - set only if the prv was received out-of-band.
   */
  async acceptShare(params: AcceptShareOptions = {}): Promise<any> {
    common.validateParams(params, ['walletShareId'], ['overrideEncryptedPrv', 'userPassword', 'newWalletPassphrase']);

    let encryptedPrv = params.overrideEncryptedPrv;

    const walletShare = (await this.getShare({ walletShareId: params.walletShareId })) as any;

    // Return right away if there is no keychain to decrypt, or if explicit encryptedPrv was provided
    if (!walletShare.keychain || !walletShare.keychain.encryptedPrv || encryptedPrv) {
      return this.updateShare({
        walletShareId: params.walletShareId,
        state: 'accepted',
      });
    }

    // More than viewing was requested, so we need to process the wallet keys using the shared ecdh scheme
    if (_.isUndefined(params.userPassword)) {
      throw new Error('userPassword param must be provided to decrypt shared key');
    }

    const sharingKeychain = (await this.bitgo.getECDHSharingKeychain()) as any;
    if (_.isUndefined(sharingKeychain.encryptedXprv)) {
      throw new Error('encryptedXprv was not found on sharing keychain');
    }

    // Now we have the sharing keychain, we can work out the secret used for sharing the wallet with us
    sharingKeychain.prv = this.bitgo.decrypt({
      password: params.userPassword,
      input: sharingKeychain.encryptedXprv,
    });
    const secret = getSharedSecret(
      // Derive key by path (which is used between these 2 users only)
      bip32.fromBase58(sharingKeychain.prv).derivePath(sanitizeLegacyPath(walletShare.keychain.path)),
      Buffer.from(walletShare.keychain.fromPubKey, 'hex')
    ).toString('hex');

    // Yes! We got the secret successfully here, now decrypt the shared wallet prv
    const decryptedSharedWalletPrv = this.bitgo.decrypt({
      password: secret,
      input: walletShare.keychain.encryptedPrv,
    });

    // We will now re-encrypt the wallet with our own password
    const newWalletPassphrase = params.newWalletPassphrase || params.userPassword;
    encryptedPrv = this.bitgo.encrypt({
      password: newWalletPassphrase,
      input: decryptedSharedWalletPrv,
    });
    const updateParams: UpdateShareOptions = {
      walletShareId: params.walletShareId,
      state: 'accepted',
    };

    if (encryptedPrv) {
      updateParams.encryptedPrv = encryptedPrv;
    }

    return this.updateShare(updateParams);
  }

  /**
   * Get a wallet by its ID
   * @param params
   * @param params.id wallet id
   * @returns {*}
   */
  async getWallet(params: GetWalletOptions = {}): Promise<Wallet> {
    common.validateParams(params, ['id'], []);

    const query: GetWalletOptions = {};
    if (params.allTokens) {
      if (!_.isBoolean(params.allTokens)) {
        throw new Error('invalid allTokens argument, expecting boolean');
      }
      query.allTokens = params.allTokens;
    }

    this.bitgo.setRequestTracer(params.reqId || new RequestTracer());

    const wallet = await this.bitgo
      .get(this.baseCoin.url('/wallet/' + params.id))
      .query(query)
      .result();
    return new Wallet(this.bitgo, this.baseCoin, wallet);
  }

  /**
   * Get a wallet by its address
   * @param params
   * @param params.address wallet address
   * @returns {*}
   */
  async getWalletByAddress(params: GetWalletByAddressOptions = {}): Promise<Wallet> {
    common.validateParams(params, ['address'], []);

    this.bitgo.setRequestTracer(params.reqId || new RequestTracer());

    const wallet = await this.bitgo.get(this.baseCoin.url('/wallet/address/' + params.address)).result();
    return new Wallet(this.bitgo, this.baseCoin, wallet);
  }

  /**
   * For any given supported coin, get total balances for all wallets of that
   * coin type on the account.
   * @param params
   * @returns {*}
   */
  async getTotalBalances(params: Record<string, never> = {}): Promise<any> {
    return await this.bitgo.get(this.baseCoin.url('/wallet/balances')).result();
  }

  /* MARK: Tss wallet creation + helpers */
  async tssCreateUserKeychain(
    userGpgKey: openpgp.SerializedKeyPair<string>,
    userKeyShare: KeyShare,
    backupKeyShare: KeyShare,
    bitgoKeychain: Keychain,
    passphrase: string
  ): Promise<Keychain> {
    const MPC = await Eddsa();
    const bitgoKeyShares = bitgoKeychain.keyShares;
    if (!bitgoKeyShares) {
      throw new Error('Missing BitGo key shares');
    }

    const bitGoToUserShare = bitgoKeyShares.find((keyShare) => keyShare.from === 'bitgo' && keyShare.to === 'user');
    if (!bitGoToUserShare) {
      throw new Error('Missing BitGo to User key share');
    }

    const bitGoToUserPrivateShareMessage = await openpgp.readMessage({
      armoredMessage: bitGoToUserShare.privateShare,
    });
    const userGpgPrivateKey = await openpgp.readPrivateKey({ armoredKey: userGpgKey.privateKey });

    const bitGoToUserPrivateShare = (
      await openpgp.decrypt({
        message: bitGoToUserPrivateShareMessage,
        decryptionKeys: [userGpgPrivateKey],
        format: 'utf8',
      })
    ).data;

    // type = YShare
    const bitgoToUser = {
      i: '1',
      j: '3',
      y: Buffer.from(bs58.decode(bitGoToUserShare.publicShare)).toString('hex'),
      u: bitGoToUserPrivateShare,
    };

    console.log(bitgoToUser);

    const userCombined = MPC.keyCombine(userKeyShare.uShare, [backupKeyShare.yShares[1], bitgoToUser]);

    return await this.baseCoin.keychains().add({
      source: 'user',
      type: 'tss',
      commonPub: bs58.encode(Buffer.from(userCombined.pShare.y, 'hex')),
      encryptedPrv: this.bitgo.encrypt({ input: JSON.stringify(userCombined.pShare), password: passphrase }),
    });
  }

  async tssCreateBackupKeychain(
    userGpgKey: openpgp.SerializedKeyPair<string>,
    userKeyShare: KeyShare,
    backupKeyShare: KeyShare,
    bitgoKeychain: Keychain,
    passphrase: string
  ): Promise<Keychain> {
    const MPC = await Eddsa();
    const bitgoKeyShares = bitgoKeychain.keyShares;
    if (!bitgoKeyShares) {
      throw new Error('Invalid bitgo keyshares');
    }

    console.log('bitgoKeyShares', JSON.stringify(bitgoKeyShares, undefined, 2));

    const bitGoToBackupShare = bitgoKeyShares.find((keyShare) => keyShare.from === 'bitgo' && keyShare.to === 'backup');
    if (!bitGoToBackupShare) {
      throw new Error('Missing BitGo to User key share');
    }

    const bitGoToBackupPrivateShareMessage = await openpgp.readMessage({
      armoredMessage: bitGoToBackupShare.privateShare,
    });
    const userGpgPrivateKey = await openpgp.readPrivateKey({ armoredKey: userGpgKey.privateKey });

    const bitGoToUserPrivateShare = (
      await openpgp.decrypt({
        message: bitGoToBackupPrivateShareMessage,
        decryptionKeys: [userGpgPrivateKey],
        format: 'utf8',
      })
    ).data;

    // type = YShare
    const bitgoToBackup = {
      i: '2',
      j: '3',
      y: Buffer.from(bs58.decode(bitGoToBackupShare.publicShare)).toString('hex'),
      u: bitGoToUserPrivateShare,
    };

    const backupCombined = MPC.keyCombine(backupKeyShare.uShare, [userKeyShare.yShares[2], bitgoToBackup]);

    return await this.baseCoin.keychains().add({
      source: 'backup',
      type: 'tss',
      commonPub: bs58.encode(Buffer.from(backupCombined.pShare.y, 'hex')),
      encryptedPrv: this.bitgo.encrypt({ input: JSON.stringify(backupCombined.pShare), password: passphrase }),
    });
  }

  private inputToString(input: Buffer | string): string {
    return Buffer.from(input).toString('hex');
  }

  async tssCreateBitgoKeychain(
    userGpgKey: openpgp.SerializedKeyPair<string>,
    userKeyShare: KeyShare,
    backupKeyShare: KeyShare,
    // TODO: test only param
    bitgoKeyShare?: KeyShare
  ): Promise<Keychain> {
    const constants = await this.bitgo.fetchConstants();
    const bitgoPublicKeyStr = constants.tss.bitgoPublicKey as string;
    const bitgoKey = await openpgp.readKey({ armoredKey: bitgoPublicKeyStr });

    const userToBitGoMessage = await openpgp.createMessage({ text: this.inputToString(userKeyShare.yShares[3].u) });
    const encUserToBitGoMessage = await openpgp.encrypt({
      message: userToBitGoMessage,
      encryptionKeys: [bitgoKey],
      format: 'armored',
      config: {
        rejectCurves: new Set(),
        showVersion: false,
        showComment: false,
      },
    });

    const backupToBitGoMessage = await openpgp.createMessage({ text: this.inputToString(backupKeyShare.yShares[3].u) });
    const encBackupToBitGoMessage = await openpgp.encrypt({
      message: backupToBitGoMessage,
      encryptionKeys: [bitgoKey],
      format: 'armored',
      config: {
        rejectCurves: new Set(),
        showVersion: false,
        showComment: false,
      },
    });

    const userPublicShare = bs58.encode(Buffer.from(userKeyShare.yShares[3].y, 'hex'));
    const backupPublicShare = bs58.encode(Buffer.from(backupKeyShare.yShares[3].y, 'hex'));

    const createBitGoTssParams = {
      type: 'tss',
      source: 'bitgo',
      keyShares: [
        {
          from: 'user',
          to: 'bitgo',
          publicShare: userPublicShare,
          privateShare: encUserToBitGoMessage,
        },
        {
          from: 'backup',
          to: 'bitgo',
          publicShare: backupPublicShare,
          privateShare: encBackupToBitGoMessage,
        },
      ],
      userGPGPublicKey: userGpgKey.publicKey,
      // TODO: Create a separate GPG key?
      backupGPGPublicKey: userGpgKey.publicKey,
    };

    console.log('createBitGoTssParams', JSON.stringify(createBitGoTssParams, undefined, 2));
    console.log();

    return await this.baseCoin.keychains().add(createBitGoTssParams);
  }

  async generateTssKeyChains(params: {
    label: string;
    passphrase: string;
    userKeyShare?: KeyShare; // TODO: test only
    backupKeyShare?: KeyShare; // TODO: test only
    bitgoKeyShare?: KeyShare; // TODO: test only
  }): Promise<KeychainsTriplet> {
    const MPC = await Eddsa();
    const m = 2;
    const n = 3;

    // USER = 1, BACKUP = 2, BITGO = 3

    const userKeyShare = params.userKeyShare || MPC.keyShare(1, m, n);
    const backupKeyShare = params.backupKeyShare || MPC.keyShare(2, m, n);

    const userGpgKey = await openpgp.generateKey({
      userIDs: [
        {
          name: 'randomstring',
          email: 'randomstring@random.com',
        },
      ],
    });

    const bitgoKeychain = await this.tssCreateBitgoKeychain(
      userGpgKey,
      userKeyShare,
      backupKeyShare,
      params.bitgoKeyShare
    );
    console.log('bitgoKeychain', JSON.stringify(bitgoKeychain, undefined, 2));
    const userKeychain = await this.tssCreateUserKeychain(
      userGpgKey,
      userKeyShare,
      backupKeyShare,
      bitgoKeychain,
      params.passphrase
    );
    const backupKeychain = await this.tssCreateBackupKeychain(
      userGpgKey,
      userKeyShare,
      backupKeyShare,
      bitgoKeychain,
      params.passphrase
    );

    // create wallet
    const keychains = {
      userKeychain,
      backupKeychain,
      bitgoKeychain,
    };

    return keychains;
  }

  /**
   * Generates a TSS wallet
   * TODO: merge with `generateWallet`
   *
   * @param params
   */
  async generateTssWallet(params: {
    label: string;
    passphrase: string;
    userKeyShare?: KeyShare; // TODO: test only
    backupKeyShare?: KeyShare; // TODO: test only
    bitgoKeyShare?: KeyShare; // TODO: test only
  }): Promise<any> {
    const walletParams: SupplementGenerateWalletOptions = {
      label: params.label,
      m: 2,
      n: 3,
      keys: [],
      isCold: false,
    };

    // USER = 1, BACKUP = 2, BITGO = 3
    const keychains = await this.generateTssKeyChains(params);
    const { userKeychain, backupKeychain, bitgoKeychain } = keychains;

    walletParams.keys = [userKeychain.id, backupKeychain.id, bitgoKeychain.id];
    const finalWalletParams = await this.baseCoin.supplementGenerateWallet(walletParams, keychains);
    this.bitgo.setRequestTracer(new RequestTracer());
    const newWallet = await this.bitgo.post(this.baseCoin.url('/wallet')).send(finalWalletParams).result();

    const result: WalletWithKeychains = {
      wallet: new Wallet(this.bitgo, this.baseCoin, newWallet),
      userKeychain: userKeychain,
      backupKeychain: backupKeychain,
      bitgoKeychain: bitgoKeychain,
    };

    return result;
  }
}
