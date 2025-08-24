"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const secp256k1 = __importStar(require("secp256k1"));
const keccak256_1 = __importDefault(require("keccak256"));
class WebMethod {
    /**
     *
     * @param domain domain name of the web method
     */
    constructor(domain) {
        this.domain = domain;
    }
    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, didDocument }.
     */
    async getKeys(node) {
        var _a, _b, _c;
        const privateKey = (_a = node.privateKey) === null || _a === void 0 ? void 0 : _a.toString('hex');
        const chainCode = (_b = node.chainCode) === null || _b === void 0 ? void 0 : _b.toString('hex');
        const publicKey = (_c = node.publicKey) === null || _c === void 0 ? void 0 : _c.toString('hex');
        const address = this.getAddressFromPublicKey(this.getPublicKey(privateKey, false));
        const did = `did:web:${this.domain}`;
        const { didDocument } = await this.getDocument(privateKey);
        return { did, address, privateKey, publicKey, chainCode, didDocument };
    }
    /**
     *
     * @param privateKey - private key as a hex string
     * @returns {CreateDidDocumentInterface}
     */
    async getDocument(privateKey) {
        const verificationKey = await this.createVerificationMethod(privateKey);
        const ecdsaVerificationKey = await this.createEcdsaVerificationMethod(privateKey);
        const authentication = [verificationKey.id, ecdsaVerificationKey.id];
        const didDocument = {
            '@context': 'https://w3id.org/did/v1',
            id: verificationKey.controller,
            publicKey: [verificationKey],
            verificationMethod: [ecdsaVerificationKey],
            authentication: authentication,
            assertionMethod: authentication,
            service: []
        };
        return { didDocument };
    }
    /**
     *
     * @param seed - seed as a hex string
     * @param includePrivateKey - include private key
     * @returns {VerificationKeyInterface}
     */
    async createVerificationMethod(seed, includePrivateKey = false) {
        let jwk = {
            id: '',
            controller: '',
            type: 'Secp256k1VerificationKey2018',
            publicKeyHex: ''
        };
        const privateKey = new Uint8Array(Buffer.from(seed, 'hex'));
        const verified = secp256k1.privateKeyVerify(privateKey);
        if (verified) {
            const address = this.domain;
            jwk.publicKeyHex = this.getPublicKey(seed, false, false);
            jwk.controller = `did:web:${address}`;
            jwk.id = `${jwk.controller}#owner`;
            if (includePrivateKey) {
                jwk.privateKeyHex = privateKey;
            }
        }
        return jwk;
    }
    /**
     *
     * @param seed - seed as a hex string
     * @returns {VerificationKeyInterface}
     */
    async createEcdsaVerificationMethod(seed) {
        let jwk = {
            id: '',
            controller: '',
            type: 'EcdsaSecp256k1VerificationKey2019',
            publicKeyHex: ''
        };
        const privateKey = new Uint8Array(Buffer.from(seed, 'hex'));
        const verified = secp256k1.privateKeyVerify(privateKey);
        const address = this.domain;
        if (verified) {
            jwk.publicKeyHex = this.getPublicKey(seed, true);
            jwk.controller = `did:web:${address}`;
            jwk.id = `${jwk.controller}#ecdsa`;
        }
        return jwk;
    }
    getPublicKey(privateKey, compressed = true, removeFlag = true) {
        const privateKeyBuffer = Buffer.from(Buffer.from(privateKey, 'hex'));
        let publicKeyBuffer = secp256k1.publicKeyCreate(privateKeyBuffer, compressed);
        /* remove compressed flag */
        if (!compressed && removeFlag)
            publicKeyBuffer = publicKeyBuffer.slice(1);
        return Buffer.from(publicKeyBuffer).toString('hex');
    }
    getAddressFromPublicKey(publicKey) {
        const publicKeyBuffer = Buffer.from(publicKey, 'hex');
        const addressBuffer = Buffer.from((0, keccak256_1.default)(publicKeyBuffer)).slice(-20);
        return `0x${addressBuffer.toString('hex')}`;
    }
}
exports.default = WebMethod;
//# sourceMappingURL=index.js.map