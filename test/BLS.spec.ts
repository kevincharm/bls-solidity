import { ethers } from 'hardhat'
import { TestBLS, TestBLS__factory } from '../typechain-types'
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers'
import { hexlify, randomBytes } from 'ethers'
import { expect } from 'chai'
import { Mcl } from '../lib/Mcl'

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
        const msg = hexlify(randomBytes(12)) as `0x${string}`
        const { signature, M } = mcl.sign(msg, secretKey)

        const args = mcl.toArgs(pubKey, M, signature)
        expect(await testBLS.verifySingle(args.signature, args.pubKey, args.M)).to.eq(true)
    })
})
