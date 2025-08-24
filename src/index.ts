import * as secp256k1 from 'secp256k1';
import keccak256 from 'keccak256';

export default class WebMethod {
    private domain: string;

    /**
     *
     * @param domain domain name of the web method
     */
    constructor(domain: string) {
        this.domain = domain;
    }

    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, didDocument }.
     */
    async getKeys(node: BIP32Interface): Promise<KeysInterface> {
        const privateKey = node.privateKey?.toString('hex');
        const chainCode = node.chainCode?.toString('hex');
        const publicKey = node.publicKey?.toString('hex') as string;
        const address = this.getAddressFromPublicKey(
            this.getPublicKey(privateKey as string, false)
        );
        const did = `did:web:${this.domain}`;

        const { didDocument } = await this.getDocument(privateKey as string);

        return { did, address, privateKey, publicKey, chainCode, didDocument };
    }

    /**
     *
     * @param privateKey - private key as a hex string
     * @returns {CreateDidDocumentInterface}
     */
    async getDocument(privateKey: string): Promise<CreateDidDocumentInterface> {
        const verificationKey: VerificationKeyInterface =
            await this.createVerificationMethod(privateKey);
        const ecdsaVerificationKey: VerificationKeyInterface =
            await this.createEcdsaVerificationMethod(privateKey);

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
    async createVerificationMethod(
        seed: string,
        includePrivateKey: boolean = false
    ): Promise<VerificationKeyInterface> {
        let jwk: VerificationKeyInterface = {
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
    async createEcdsaVerificationMethod(seed: string): Promise<VerificationKeyInterface> {
        let jwk: VerificationKeyInterface = {
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

    private getPublicKey(
        privateKey: string,
        compressed: boolean = true,
        removeFlag: boolean = true
    ): string {
        const privateKeyBuffer = Buffer.from(Buffer.from(privateKey, 'hex'));

        let publicKeyBuffer = secp256k1.publicKeyCreate(privateKeyBuffer, compressed);

        /* remove compressed flag */
        if (!compressed && removeFlag) publicKeyBuffer = publicKeyBuffer.slice(1);

        return Buffer.from(publicKeyBuffer).toString('hex');
    }

    private getAddressFromPublicKey(publicKey: string): string {
        const publicKeyBuffer = Buffer.from(publicKey, 'hex');
        const addressBuffer = Buffer.from(keccak256(publicKeyBuffer)).slice(-20);

        return `0x${addressBuffer.toString('hex')}`;
    }
}
