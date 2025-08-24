export default class WebMethod {
    private domain;
    /**
     *
     * @param domain domain name of the web method
     */
    constructor(domain: string);
    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, didDocument }.
     */
    getKeys(node: BIP32Interface): Promise<KeysInterface>;
    /**
     *
     * @param privateKey - private key as a hex string
     * @returns {CreateDidDocumentInterface}
     */
    getDocument(privateKey: string): Promise<CreateDidDocumentInterface>;
    /**
     *
     * @param seed - seed as a hex string
     * @param includePrivateKey - include private key
     * @returns {VerificationKeyInterface}
     */
    createVerificationMethod(seed: string, includePrivateKey?: boolean): Promise<VerificationKeyInterface>;
    /**
     *
     * @param seed - seed as a hex string
     * @returns {VerificationKeyInterface}
     */
    createEcdsaVerificationMethod(seed: string): Promise<VerificationKeyInterface>;
    private getPublicKey;
    private getAddressFromPublicKey;
}
