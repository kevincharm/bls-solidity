import { ethers } from 'hardhat'
import { TestBLS, TestBLS__factory } from '../typechain-types'
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers'
import { sha256 } from 'ethers'
import { expect } from 'chai'
import { Mcl, kyberMarshalG1, kyberMarshalG2 } from '../lib/Mcl'

describe('BLS', () => {
    let mcl: Mcl
    before(async () => {
        mcl = await Mcl.create('testing evmbls')
    })

    let testBLS: TestBLS
    let deployer: SignerWithAddress
    beforeEach(async () => {
        ;[deployer] = await ethers.getSigners()
        testBLS = await new TestBLS__factory(deployer).deploy()
    })

    it('verify single', async () => {
        const { secretKey, pubKey } = mcl.createKeyPair()
        // const msg = hexlify(randomBytes(12)) as `0x${string}`
        // 64-bit round number, encoded in big-endian
        const roundNumber = new Uint8Array(8)
        roundNumber[7] = 1 // round = 1
        const msg = sha256(roundNumber) as `0x${string}`
        const { signature, M } = mcl.sign(msg, secretKey)

        // Kyber serialised format
        console.log('pub', kyberMarshalG2(pubKey))
        console.log('sig', kyberMarshalG1(signature))

        const args = mcl.toArgs(pubKey, M, signature)
        expect(await testBLS.isOnCurveG1(args.signature)).to.eq(true) // 400 gas
        expect(await testBLS.isOnCurveG1(args.M)).to.eq(true) // 400 gas
        expect(await testBLS.isOnSubgroupG2DLZZ(args.pubKey)).to.eq(true) // 865k gas
        expect(await testBLS.verifySingle(args.signature, args.pubKey, args.M)).to.eq(true)
        console.log('gas:', await testBLS.verifySingleGasCost(args.signature, args.pubKey, args.M))
    })
})
