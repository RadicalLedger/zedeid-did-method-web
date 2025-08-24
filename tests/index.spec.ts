import { BIP32Factory } from 'bip32';
import * as ecc from 'tiny-secp256k1';
import WebMethod from '../src/index';

describe('HD Wallet Web Method', function () {
    it('create master node', async () => {
        const seed = '000102030405060708090a0b0c0d0e0f';

        const bip32 = BIP32Factory(ecc);
        const masterNode = bip32.fromSeed(Buffer.from(seed, 'hex'));
        const webNode = masterNode.derivePath("m/44'/60'/0'/0/0");

        const webMethod = new WebMethod('radicalledger.com');
        const keys = await webMethod.getKeys(webNode);

        expect(keys).toEqual({
            did: 'did:web:radicalledger.com',
            address: '0x022b971dff0c43305e691ded7a14367af19d6407',
            privateKey: 'e22f5526ce620ec69441c3453d7a0acbc26c3fc7543023f338123fd45c7d44b3',
            publicKey: '03844a5d329470697de9926c9c98839ea33b6dd9507a896194ae2b91d71faa16d6',
            chainCode: 'dac0c414d5006b7350e3b7750e5b535af7ecd9b5a2ad00648d427349885f4358',
            didDocument: {
                '@context': 'https://w3id.org/did/v1',
                id: 'did:web:radicalledger.com',
                publicKey: [
                    {
                        id: 'did:web:radicalledger.com#owner',
                        controller: 'did:web:radicalledger.com',
                        type: 'Secp256k1VerificationKey2018',
                        publicKeyHex:
                            '04844a5d329470697de9926c9c98839ea33b6dd9507a896194ae2b91d71faa16d64b9c486b7a6395543027bc6e8c99e1967fb41718e1ab1ef66585c5c55470ca1d'
                    }
                ],
                verificationMethod: [
                    {
                        id: 'did:web:radicalledger.com#ecdsa',
                        controller: 'did:web:radicalledger.com',
                        type: 'EcdsaSecp256k1VerificationKey2019',
                        publicKeyHex:
                            '03844a5d329470697de9926c9c98839ea33b6dd9507a896194ae2b91d71faa16d6'
                    }
                ],
                authentication: [
                    'did:web:radicalledger.com#owner',
                    'did:web:radicalledger.com#ecdsa'
                ],
                assertionMethod: [
                    'did:web:radicalledger.com#owner',
                    'did:web:radicalledger.com#ecdsa'
                ],
                service: []
            }
        });
    });
});
